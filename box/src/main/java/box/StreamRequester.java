package box;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import utils.CipherSuite;
import utils.FileUtils;
import utils.HandshakeException;
import utils.HandshakeUtils;
import utils.crypto.CryptoException;

import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static utils.HandshakeUtils.*;

public class StreamRequester implements Closeable {

    private static final Logger logger = Logger.getLogger(StreamRequester.class.getName());

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
            System.err.println("Incorrect arguments, try something like:\n" +
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

        try (StreamRequester requester = new StreamRequester(address, properties, keyStore)) {

            System.out.println("Available streams:");
            List<String> streams = requester.getAvailableStreams();

            for (int i = 0; i < streams.size(); i++)
                System.out.printf("%d.\t%s\n", i + 1, streams.get(i));

            int choice = -1;
            while (choice < 0 || choice >= streams.size())
            {
                System.out.print("Pick one: ");
                choice = new Scanner(System.in).nextInt() - 1;
                if (choice < 0 || choice >= streams.size())
                    System.out.println("Invalid value.");
            }

            InetSocketAddress streamTo = new InetSocketAddress(InetAddress.getLocalHost(), 9999);

            new Thread(() -> {

                try {
                    Properties props = new Properties();
                    props.load(FileUtils.streamFromResourceOrPath("config.properties"));

                    Set<SocketAddress> addresses = Arrays.stream(props.getProperty("localdelivery").split(","))
                            .map(Box::parseSocketAddress)
                            .collect(Collectors.toSet());

                    Box.broadcast(requester.getNegotiatedCryptoConfiguration(), streamTo, addresses);
                } catch (IOException | CryptoException e) {
                    throw new RuntimeException(e);
                }
            }); // TODO .start();

            requester.requestStream(streams.get(choice));


        } catch (IOException | HandshakeException e) {
            throw new RuntimeException(e);
        }

    }

    private TrustAnchor trustAnchor;
    private List<String> availableStreams;
    private Socket socket;
    private Properties negotiatedProperties;

    public StreamRequester(InetSocketAddress serverAddress, Properties cryptoProperties, KeyStore keyStore) throws IOException, HandshakeException {

        logger.fine("Connection crypto properties:");
        cryptoProperties.forEach((o, o2) -> logger.fine(String.format("\t- %30.30s -> %30.30s\n", o, o2.toString())));

        Enumeration<String> enume = null;
        try {
            enume = keyStore.aliases();
            logger.fine("Keystore aliases:");
            while (enume.hasMoreElements())
                logger.fine(String.format("\t- %s\n", enume.nextElement()));
        } catch (KeyStoreException e) {
            System.err.println("Error reading from keystore.");
            e.printStackTrace(System.err);
        }

        // load CA certificate
        try {
            trustAnchor = new TrustAnchor((X509Certificate) keyStore.getCertificate("ca"), null);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }

        socket = new Socket(serverAddress.getAddress(), serverAddress.getPort());

        performHandshake(cryptoProperties, keyStore);
    }

    public List<String> getAvailableStreams() {
        return availableStreams;
    }

    public Properties getNegotiatedCryptoConfiguration() {
        return new Properties(); // TODO
    }

    public void requestStream(String streamName) throws IOException {
        DataOutputStream outputStream = new DataOutputStream(socket.getOutputStream());

        HandshakeUtils.sendBytes(outputStream, streamName.getBytes());
    }

    @Override
    public void close() throws IOException {
        socket.close();
    }

    private void performHandshake(Properties properties, KeyStore keyStore) throws IOException, HandshakeException {

        DataOutputStream outputStream = new DataOutputStream(socket.getOutputStream());
        DataInputStream inputStream = new DataInputStream(socket.getInputStream());

        //region Initialize parameters necessary for handshake
        KeyPair keyAgreementPair;
        KeyAgreement agreement;


        try {
            keyAgreementPair = generateKeyPair(properties.getProperty("KeyType"), properties.getProperty("KeyParams"));
            agreement = getKeyAgreement(properties.getProperty("KeyType"));
            agreement.init(keyAgreementPair.getPrivate());
        } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException |
                 InvalidKeyException e) {
            throw new ExceptionInInitializerError(e);
        }

        Certificate cert1;
        Signature mySignature;
        Mac integrityCheck;

        try {
            integrityCheck = Mac.getInstance("HmacSHA512");
            integrityCheck.init(new SecretKeySpec(properties.getProperty("MACKey").getBytes(), "HmacSHA256"));

            Key k1 = keyStore.getKey("mykeys", properties.getProperty("KSPassword").toCharArray());

            if (k1 instanceof PrivateKey) {
                cert1 = keyStore.getCertificate("myKeys");
                verifyCertificate((X509Certificate) cert1);
            }
            else
                throw new InvalidKeyException("Could not find private key.");

            mySignature = Signature.getInstance("SHA256with" + k1.getAlgorithm());
            mySignature.initSign((PrivateKey) k1);
        } catch (KeyStoreException | UnrecoverableKeyException | NoSuchAlgorithmException | CertificateException |
                 InvalidKeyException e) {
            throw new ExceptionInInitializerError(e);
        }

        short cipherSuite = parseCipherSuites(properties.getProperty("CS"));

        //endregion

        //region First message of handshake

        byte[] contents = composeHandshake(cipherSuite, keyAgreementPair.getPublic(),
                new Certificate[]{ cert1, trustAnchor.getTrustedCert() }, mySignature, integrityCheck);

        outputStream.writeInt(contents.length);
        outputStream.write(contents);
        outputStream.flush();

        //endregion

        //region Receive server response

        int messageLength = inputStream.readInt();
        byte[] message = inputStream.readNBytes(messageLength);

        ByteBuffer buffer = ByteBuffer.wrap(message);
        short cipher = buffer.getShort();

        PublicKey serverPKey = null;
        try {
            short keyLength = buffer.getShort();
            byte[] keyBytes = new byte[keyLength];
            buffer.get(keyBytes, 0, keyLength);

            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("DH");
            serverPKey = keyFactory.generatePublic(keySpec);
            agreement.doPhase(serverPKey, true);
        } catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException e) {
            throw new HandshakeException(e);
        }

        availableStreams = List.of(parseStringArray(validateHandshake(message, integrityCheck, trustAnchor)));

        int negotiatedCipherIndex = Short.SIZE;
        while (negotiatedCipherIndex > -1 && (cipher >> negotiatedCipherIndex) == 0) {
            negotiatedCipherIndex--;
        }
        System.out.printf("\tNegotiated cipher: 0b%s (%s)\n", Integer.toBinaryString(cipher), negotiatedCipherIndex);

        System.out.printf("\tNegotiated secret: %30.30s ...\n", Arrays.toString(agreement.generateSecret()));

        //endregion


    }

    private static String[] parseStringArray(byte[] bytes) {
        return new String(bytes).split("\0");
    }
}
