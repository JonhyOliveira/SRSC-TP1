package server;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import utils.HandshakeException;
import utils.HandshakeUtils;

import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Properties;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static utils.HandshakeUtils.*;

public class StreamRequestsServer {

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {

        if (args.length < 2) {
            System.err.println("Incorrect arguments, try something like:\n" +
                    "<films directory> <films extension regex> [cipher_code1,...]");
            return;
        }

        System.out.println("Provided ciphers: " + (args.length >= 3 ? Arrays.toString(args[2].split(",")) : Arrays.toString(new String[0])));

        Properties properties = new Properties();
        properties.load(StreamRequestsServer.class.getClassLoader().getResourceAsStream("request.properties"));
        if (args.length >= 3) {
            properties.setProperty("CS", // join default request property with the provided
                    Stream.concat(Arrays.stream(properties.getProperty("CS", "").split(",")),
                            Arrays.stream(args[2].split(","))).sorted().collect(Collectors.joining(",")));
        }

        KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
        keyStore.load(StreamRequestsServer.class.getClassLoader().getResourceAsStream("server.jks"),
                properties.getProperty("KSPassword").toCharArray());

        new StreamRequestsServer(properties, keyStore, new MovieFileStreamer(new File(args[0]), args[1]));
    }

    private static final int DEFAULT_PORT = 4242, DEFAULT_BACKLOG = 10;

    public StreamRequestsServer(Properties properties, KeyStore trustStore, StreamsManager manager) {
        this(DEFAULT_PORT, DEFAULT_BACKLOG, properties, trustStore, manager);
    }

    public StreamRequestsServer(int servePort, Properties properties, KeyStore trustStore, StreamsManager manager) {
        this(servePort, DEFAULT_BACKLOG, properties, trustStore, manager);
    }

    private ThreadPoolExecutor threadPoolExecutor;
    private AtomicBoolean running;
    private Properties cryptoProperties;
    private KeyStore trustStore;
    private TrustAnchor trustAnchor;
    private StreamsManager manager;

    public StreamRequestsServer(int servePort, int backlog, Properties properties, KeyStore trustStore,
                                StreamsManager manager) {
        threadPoolExecutor = new ThreadPoolExecutor(backlog, backlog, 0, TimeUnit.DAYS,
                new LinkedBlockingQueue<>());
        running = new AtomicBoolean(true);
        cryptoProperties = properties;
        this.trustStore = trustStore;
        this.manager = manager;

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

        // load CA certificate
        try {
            trustAnchor = new TrustAnchor((X509Certificate) trustStore.getCertificate("ca"), null);
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }

        System.out.println("Serving streams: " + manager.getAvailableStreams());

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

                Mac integrityCheck;

                try {
                    integrityCheck = Mac.getInstance("HmacSHA512");
                    integrityCheck.init(new SecretKeySpec(server.cryptoProperties.getProperty("MACKey").getBytes(), "HmacSHA256"));
                } catch (NoSuchAlgorithmException | InvalidKeyException e) {
                    throw new ExceptionInInitializerError(e);
                }

                //endregion

                //region Parse and Verify Handshake message
                int messageLength = inputStream.readInt();
                byte[] message = inputStream.readNBytes(messageLength);

                ByteBuffer buffer = ByteBuffer.wrap(message);
                short clientCiphers = buffer.getShort();

                PublicKey clientPKey = null;
                try {
                    short keyLength = buffer.getShort();
                    byte[] keyBytes = new byte[keyLength];
                    buffer.get(keyBytes, 0, keyLength);

                    X509EncodedKeySpec keySpec = new X509EncodedKeySpec(keyBytes);
                    KeyFactory keyFactory = KeyFactory.getInstance("DH");
                    clientPKey = keyFactory.generatePublic(keySpec);
                    agreement.doPhase(clientPKey, true);
                } catch (NoSuchAlgorithmException | InvalidKeySpecException | InvalidKeyException e) {
                    throw new HandshakeException(e);
                }

                validateHandshake(message, integrityCheck, server.trustAnchor);

                //endregion

                //region Load parameters necessary for response
                Certificate cert;
                Signature signature;

                try {

                    Key k1 = server.trustStore.getKey("myKeys", server.cryptoProperties.getProperty("KSPassword").toCharArray());

                    if (k1 instanceof PrivateKey) {
                        cert = server.trustStore.getCertificate("myKeys");
                        verifyCertificate((X509Certificate) cert);
                    }
                    else
                        throw new InvalidKeyException("Could not find private key.");

                    signature = Signature.getInstance("SHA256with" + k1.getAlgorithm());
                    signature.initSign((PrivateKey) k1);

                } catch (UnrecoverableKeyException | CertificateException | NoSuchAlgorithmException | KeyStoreException |
                         InvalidKeyException e) {
                    throw new ExceptionInInitializerError(e);
                }

                short preferedCipherSuite;
                { // calculate prefered cipher suite
                    short supportedCipherSuites = parseCipherSuites(server.cryptoProperties.getProperty("CS"));

                    int i;
                    for (i = Short.SIZE; i > 0; i--)
                        if ((supportedCipherSuites & clientCiphers) >>i != 0)
                            break; // index of first match left to right

                    preferedCipherSuite = (short) (1 << (i));

                    if ((preferedCipherSuite & Short.MAX_VALUE) == 0)
                        throw new HandshakeException("Could not find common grounds for cipher suite.");

                    System.out.printf("\tNegotiated cipher: 0b%s (%s)\n", Integer.toBinaryString(preferedCipherSuite), preferedCipherSuite);
                }
                System.out.printf("\tNegotiated secret: %30.30s ...\n", Arrays.toString(agreement.generateSecret()));

                //endregion

                //region Send Handshake Message

                byte[] contents = composeHandshake(preferedCipherSuite, keyAgreementPair.getPublic(),
                        new Certificate[]{ cert, server.trustAnchor.getTrustedCert() }, signature, integrityCheck,
                        String.join("\0", server.manager.getAvailableStreams()).getBytes());

                outputStream.writeInt(contents.length);
                outputStream.write(contents);
                outputStream.flush();

                //endregion

                //region Receive Control Message
                String choice = new String(HandshakeUtils.receiveBytes(inputStream));

                System.out.printf("\tChoice: %s\n", choice);

                //endregion

                int negotiatedCipherIndex = Short.SIZE;
                while (negotiatedCipherIndex > -1 && (preferedCipherSuite >> negotiatedCipherIndex) == 0) {
                    negotiatedCipherIndex--;
                }


                // TODO setup crypto properties and start stream

            } catch (IOException | HandshakeException  e) {
                throw new RuntimeException(e);
            }
        }
    }

}
