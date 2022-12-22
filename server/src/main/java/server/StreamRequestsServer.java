package server;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import rtssp.Handshake;
import utils.HandshakeException;
import utils.LengthPreappendInputStream;
import utils.LengthPreappendOutputStream;
import utils.crypto.CryptoException;

import java.io.*;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.security.cert.CertificateException;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Properties;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;
import java.util.stream.Stream;

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
                InputStream inputStream = new LengthPreappendInputStream<>(socket.getInputStream(), Integer.class);
                OutputStream outputStream = new LengthPreappendOutputStream<>(socket.getOutputStream(), Integer.class);

                Handshake handshake = new Handshake(server.cryptoProperties, server.trustStore, 2);

                handshake.receiveMessage(inputStream.readAllBytes());
                handshake.sendMessage(outputStream, String.join("\0", server.manager.getAvailableStreams()).getBytes());

                try {
                    handshake.establishSecrets();
                } catch (CryptoException e) {
                    throw new HandshakeException(e);
                }

                Properties negotiatedProperties = handshake.getSharedSecrets();

                System.out.println("\tNegotiated properties:");
                negotiatedProperties.forEach((o, o2) -> System.out.printf("\t- %-15.15s -> %30.30s\n", o, o2.toString()));

                //Receive Control Message
                String choice = new String(inputStream.readAllBytes());

                System.out.printf("\tChoice: %s\n", choice);

                StreamServer streamer = StreamServer.getInstance(new InetSocketAddress(socket.getInetAddress(), 9999));

                streamer.stream(new StreamInfo(choice, new DataInputStream(server.manager.getStream(choice)), negotiatedProperties));
                if (!streamer.isRunning())
                    new Thread(streamer).start();

            } catch (IOException | HandshakeException  e) {
                throw new RuntimeException(e);
            }
        }
    }

}
