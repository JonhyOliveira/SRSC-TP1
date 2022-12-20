package box;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import utils.HandshakeException;

import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static utils.crypto.CryptoUtil.*;

public class StreamRequester {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {

        InetSocketAddress address = null;

        if (args.length >= 1) {
            String[] addr = args[0].split(":");
            address = new InetSocketAddress(addr[0], Integer.parseInt(addr[1]));
        }
        else {
            System.out.println("Incorrect arguments, try something like:\n" +
                    "<stream request IPv4 Host>:<Port> [cipher_code1,...]");
            return;
        }

        Properties properties = new Properties();
        properties.load(StreamRequester.class.getClassLoader().getResourceAsStream("request.properties"));
        if (args.length >= 2) {
            properties.setProperty("CS", // join default request property with the provided
                    Stream.concat(Arrays.stream(properties.getProperty("CS", "").split(",")),
                            Arrays.stream(args[1].split(","))).sorted().collect(Collectors.joining(",")));
        }

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(StreamRequester.class.getClassLoader().getResourceAsStream("box.jks"),
                properties.getProperty("KSPassword").toCharArray());

        try {
            new StreamRequester(address, properties, keyStore);
        } catch (IOException | HandshakeException e) {
            throw new RuntimeException(e);
        }

    }

    public StreamRequester(InetSocketAddress serverAddress, Properties cryptoProperties, KeyStore keyStore) throws IOException, HandshakeException {
        performHandshake(serverAddress, cryptoProperties, keyStore);
    }

    public void performHandshake(InetSocketAddress address, Properties properties, KeyStore keyStore) throws IOException, HandshakeException {

        try (Socket socket = new Socket(address.getAddress(), address.getPort())) {

            DataOutputStream outputStream = new DataOutputStream(socket.getOutputStream());
            DataInputStream inputStream = new DataInputStream(socket.getInputStream());

            //region Initialize parameters necessary for handshake
            KeyPair keyAgreementPair;
            KeyAgreement agreement;

            System.out.println("Connection crypto properties");
            properties.forEach((o, o2) -> System.out.printf("%30.30s -> %30.30s\n", o, o2.toString()));

            Enumeration<String> enume = null;
            try {
                enume = keyStore.aliases();
            } catch (KeyStoreException e) {
                throw new RuntimeException(e);
            }
            System.out.println("Keystore aliases:");
            while (enume.hasMoreElements())
                System.out.printf("- %s\n", enume.nextElement());

            try {
                keyAgreementPair = generateKeyPair(properties.getProperty("KeyType"), properties.getProperty("KeyParams"));
                agreement = getKeyAgreement(properties.getProperty("KeyType"));
                agreement.init(keyAgreementPair.getPrivate());
            } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException |
                     InvalidKeyException e) {
                throw new ExceptionInInitializerError(e);
            }

            Certificate cert1;
            Signature signature;
            Mac integrityCheck;

            try {
                signature = Signature.getInstance("SHA256withDSA");
                integrityCheck = Mac.getInstance("HmacSHA512");
                integrityCheck.init(new SecretKeySpec(properties.getProperty("MACKey").getBytes(), "HmacSHA256"));

                Key k1 = keyStore.getKey("box-dsa", properties.getProperty("KSPassword").toCharArray());

                if (k1 instanceof PrivateKey) {
                    cert1 = keyStore.getCertificate("box-dsa");
                    verifyCertificate((X509Certificate) cert1);
                    signature.initSign((PrivateKey) k1);
                }
                else
                    throw new InvalidKeyException("Could not find private key.");

            } catch (KeyStoreException | UnrecoverableKeyException | NoSuchAlgorithmException | CertificateException |
                     InvalidKeyException e) {
                throw new ExceptionInInitializerError(e);
            }

            short cipherSuite = parseCipherSuites(properties.getProperty("CS"));

            //endregion

            //region First message of handshake

            // build contents
            ByteArrayOutputStream baos = new ByteArrayOutputStream();
            {
                DataOutputStream outStream = new DataOutputStream(baos);

                try {
                    outStream.writeShort(cipherSuite);
                    // send my key exchange
                    outStream.writeShort((short) keyAgreementPair.getPublic().getEncoded().length);
                    outStream.write(keyAgreementPair.getPublic().getEncoded());
                    Certificate[] certChain = new Certificate[] { cert1 };
                    // send certificate chain
                    outStream.writeShort((short) certChain.length);
                    for (Certificate certificate : certChain) {
                        byte[] encoded = certificate.getEncoded();
                        outStream.writeShort((short) encoded.length);
                        outStream.write(encoded);
                    }
                    outStream.flush();

                    signature.update(baos.toByteArray());
                    byte[] sign = signature.sign();
                    outStream.write(sign);
                    outStream.writeShort(sign.length);
                    outStream.flush();

                    integrityCheck.update(baos.toByteArray());
                    outStream.write(integrityCheck.doFinal());

                } catch (SignatureException | CertificateEncodingException e) {
                    throw new HandshakeException(e);
                }
                outStream.flush();
            }
            // send it
            byte[] contents = baos.toByteArray();

            outputStream.writeInt(contents.length);
            outputStream.write(contents);
            outputStream.flush();

            //endregion

        }

    }

}
