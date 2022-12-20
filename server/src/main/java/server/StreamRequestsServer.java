package server;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import utils.HandshakeException;

import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Properties;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static utils.crypto.CryptoUtil.*;

public class StreamRequestsServer {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {

        System.out.println("Provided ciphers: " + (args.length > 0 ? Arrays.toString(args[0].split(",")) : Arrays.toString(new String[0])));

        Properties properties = new Properties();
        properties.load(StreamRequestsServer.class.getClassLoader().getResourceAsStream("request.properties"));
        if (args.length >= 2) {
            properties.setProperty("CS", // join default request property with the provided
                    Stream.concat(Arrays.stream(properties.getProperty("CS", "").split(",")),
                            Arrays.stream(args[1].split(","))).sorted().collect(Collectors.joining(",")));
        }

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(StreamRequestsServer.class.getClassLoader().getResourceAsStream("server.jks"),
                properties.getProperty("KSPassword").toCharArray());

        new StreamRequestsServer(properties, keyStore);
    }

    private static final int DEFAULT_PORT = 4242, DEFAULT_BACKLOG = 10;

    public StreamRequestsServer(Properties properties, KeyStore trustStore) {
        this(DEFAULT_PORT, DEFAULT_BACKLOG, properties, trustStore);
    }

    public StreamRequestsServer(int servePort, Properties properties, KeyStore trustStore) {
        this(servePort, DEFAULT_BACKLOG, properties, trustStore);
    }

    private ThreadPoolExecutor threadPoolExecutor;
    private AtomicBoolean running;
    private Properties cryptoProperties;
    private KeyStore trustStore;

    public StreamRequestsServer(int servePort, int backlog, Properties properties, KeyStore trustStore) {
        threadPoolExecutor = new ThreadPoolExecutor(backlog, backlog, 0, TimeUnit.DAYS,
                new LinkedBlockingQueue<>());
        running = new AtomicBoolean(true);
        cryptoProperties = properties;
        this.trustStore = trustStore;

        System.out.println("Connection crypto properties:");
        cryptoProperties.forEach((o, o2) -> System.out.printf("%30.30s -> %30.30s\n", o, o2.toString()));
        try {
            Enumeration<String> enume = trustStore.aliases();
            System.out.println("Keystore aliases:");
            while (enume.hasMoreElements())
                System.out.printf("- %s\n", enume.nextElement());
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }
        try (ServerSocket server = new ServerSocket(servePort, backlog)) {
            System.out.printf("Listening @ %s:%s\n", server.getInetAddress().getHostAddress(), server.getLocalPort());
            while (running.get())
                threadPoolExecutor.execute(new ClientRequestHandler(server.accept(), this));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static class ClientRequestHandler implements Runnable {

        private Socket clientSocket;
        private StreamRequestsServer server;

        public ClientRequestHandler(Socket clientSocket, StreamRequestsServer server) {
            this.clientSocket = clientSocket;
            this.server = server;
        }

        @Override
        public void run() {
            System.out.printf("Connection from %s.\n", clientSocket.getInetAddress());

            try (Socket socket = this.clientSocket) {
                DataInputStream inputStream = new DataInputStream(socket.getInputStream());
                DataOutputStream outputStream = new DataOutputStream(socket.getOutputStream());

                //region Initialize parameters necessary to handle request

                KeyPair keyAgreementPair;
                KeyAgreement agreement;

                try {
                    keyAgreementPair = generateKeyPair(server.cryptoProperties.getProperty("KeyType"),
                            server.cryptoProperties.getProperty("KeyParams"));
                    agreement = getKeyAgreement(server.cryptoProperties.getProperty("KeyType"));
                    agreement.init(keyAgreementPair.getPrivate());
                } catch (NoSuchAlgorithmException | NoSuchProviderException | InvalidAlgorithmParameterException |
                         InvalidKeyException e) {
                    throw new ExceptionInInitializerError(e);
                }

                Mac clientIntegrityCheck;

                try {
                    clientIntegrityCheck = Mac.getInstance("HmacSHA512");
                    clientIntegrityCheck.init(new SecretKeySpec(server.cryptoProperties.getProperty("MACKey").getBytes(), "HmacSHA256"));
                } catch (NoSuchAlgorithmException | InvalidKeyException e) {
                    throw new ExceptionInInitializerError(e);
                }

                //endregion

                //region Parse and Verify Handshake message
                int messageLength = inputStream.readInt();
                byte[] message = inputStream.readNBytes(messageLength);
                short clientCiphers = 0;

                try {
                    // first, check MAC
                    byte[] check = Arrays.copyOfRange(message, message.length - clientIntegrityCheck.getMacLength(), message.length),
                            remainder = Arrays.copyOfRange(message, 0, message.length - clientIntegrityCheck.getMacLength());

                    if (!Arrays.equals(check, clientIntegrityCheck.doFinal(remainder)))
                        throw new HandshakeException("Corrupted message failed integrity check");

                    System.out.println("Integrity: OK");

                    // second, check signature
                    ByteBuffer buf = ByteBuffer.wrap(remainder);
                    int len = buf.getShort(remainder.length - Short.BYTES); // signature length
                    byte[] sign = Arrays.copyOfRange(remainder,
                            remainder.length - Short.BYTES - len, remainder.length - Short.BYTES);

                    //   certificates and keys
                    clientCiphers = buf.getShort();
                    len = buf.getShort(); // key agreement public key
                    byte[] bytes = new byte[len];
                    buf.get(bytes, 0, len);
                    PublicKey other = publicKeyParser(bytes, server.cryptoProperties.getProperty("KeyType"));
                    len = buf.getShort(); // certificate chain size

                    X509Certificate[] clientCertChain = new X509Certificate[len];

                    for (int i = 0; i < len; i++) {
                        int certLen = buf.getShort();
                        bytes = new byte[certLen];
                        buf.get(bytes, 0, certLen);
                        clientCertChain[i] = certificateParser(bytes);
                        verifyCertificate(clientCertChain[i]);
                    }

                    Signature signature = Signature.getInstance("SHA256withDSA");
                    signature.initVerify(clientCertChain[0]);
                    signature.update(Arrays.copyOfRange(remainder, 0, remainder.length - Short.BYTES - sign.length));
                    if (!signature.verify(sign))
                        throw new HandshakeException("Message signature is invalid");
                } catch (NoSuchAlgorithmException | SignatureException | InvalidKeyException | CertificateException e) {
                    throw new RuntimeException(e);
                }
                System.out.println("Signature: OK");

                // TODO load CA certificate and verify if chain is trustable
                // validateChain(new TrustAnchor(CACert, null), certChain);
                System.out.println("Trustable.");

                //endregion

                //region Load parameters necessary for response
                Certificate cert;
                Signature signature;
                Mac integrityCheck;

                try {
                    signature = Signature.getInstance("SHA256withDSA");
                    integrityCheck = Mac.getInstance("HmacSHA512");
                    integrityCheck.init(new SecretKeySpec(server.cryptoProperties.getProperty("MACKey").getBytes(), "HmacSHA256"));

                    Key k1 = server.trustStore.getKey("serv-ec", server.cryptoProperties.getProperty("KSPassword").toCharArray());

                    if (k1 instanceof PrivateKey) {
                        cert = server.trustStore.getCertificate("serv-ec");
                        verifyCertificate((X509Certificate) cert);
                        signature.initSign((PrivateKey) k1);
                    }
                    else
                        throw new InvalidKeyException("Could not find private key.");
                } catch (UnrecoverableKeyException | CertificateException | NoSuchAlgorithmException | KeyStoreException |
                         InvalidKeyException e) {
                    throw new ExceptionInInitializerError(e);
                }

                short preferedCipherSuite;
                { // calculate prefered cipher suite
                    short supportedCipherSuites = parseCipherSuites(server.cryptoProperties.getProperty("CS"));

                    int i = Short.SIZE;
                    while (i > 0 && (supportedCipherSuites & clientCiphers) >>i != 0)
                        i--; // index of first match left to right

                    preferedCipherSuite = (short) (1 << (i));
                }

                //endregion

                //region Send Handshake Message
                ByteArrayOutputStream baos = new ByteArrayOutputStream();
                {
                    DataOutputStream outStream = new DataOutputStream(baos);
                    try {

                        outStream.writeShort(preferedCipherSuite);
                        // send my key exchange
                        outStream.writeShort((short) keyAgreementPair.getPublic().getEncoded().length);
                        outStream.write(keyAgreementPair.getPublic().getEncoded());
                        Certificate[] certChain = new Certificate[]{cert};
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
                byte[] contents = baos.toByteArray();

                outputStream.writeInt(contents.length);
                outputStream.write(contents);
                outputStream.flush();

                //endregion

            } catch (IOException | HandshakeException  e) {
                throw new RuntimeException(e);
            }
        }
    }

}
