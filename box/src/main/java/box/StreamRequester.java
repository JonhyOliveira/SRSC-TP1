package box;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import rtssp.Handshake;
import utils.*;
import utils.crypto.CryptoException;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketAddress;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.TrustAnchor;
import java.util.*;
import java.util.logging.Logger;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static utils.StreamUtils.sendBytes;

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

            InetSocketAddress streamTo = new InetSocketAddress("127.0.0.1", 9999);

            new Thread(() -> {
                try {
                    Set<SocketAddress> addresses = Set.of(new InetSocketAddress("224.7.7.7", 7777));
                    Box.broadcast(requester.getNegotiatedCryptoConfiguration(), streamTo, addresses);
                } catch (IOException | CryptoException e) {
                    throw new RuntimeException(e);
                }
            }).start();

            requester.requestStream(streams.get(choice));


        } catch (IOException | HandshakeException e) {
            throw new RuntimeException(e);
        }

    }

    private TrustAnchor trustAnchor;
    private List<String> availableStreams;
    private Socket socket;
    private Handshake handshake;
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

        handshake = new Handshake(cryptoProperties, keyStore, 2);
        socket = new Socket(serverAddress.getAddress(), serverAddress.getPort());

        performHandshake();
    }

    public List<String> getAvailableStreams() {
        return availableStreams;
    }

    public Properties getNegotiatedCryptoConfiguration() {
        return handshake.getSharedSecrets();
    }

    public void requestStream(String streamName) throws IOException {
        DataOutputStream outputStream = new DataOutputStream(socket.getOutputStream());

        sendBytes(outputStream, streamName.getBytes());
    }

    @Override
    public void close() throws IOException {
        socket.close();
    }

    private void performHandshake() throws IOException, HandshakeException {

        handshake.sendMessage(new LengthPreappendOutputStream(socket.getOutputStream()));
        availableStreams = List.of(parseStringArray(
                handshake.receiveMessage(new LengthPreappendInputStream(socket.getInputStream()).readAllBytes())
        ));

        try {
            handshake.establishSecrets();
        } catch (CryptoException e) {
            throw new HandshakeException(e);
        }

        System.out.println("\tNegotiated properties:");
        handshake.getSharedSecrets().forEach((o, o2) -> System.out.printf("\t- %-15.15s -> %30.30s\n", o, o2.toString()));

    }

    private static String[] parseStringArray(byte[] bytes) {
        return new String(bytes).split("\0");
    }
}
