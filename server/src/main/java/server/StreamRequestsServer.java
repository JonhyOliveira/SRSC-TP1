package server;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.Properties;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.SynchronousQueue;
import java.util.concurrent.ThreadPoolExecutor;
import java.util.concurrent.TimeUnit;

public class StreamRequestsServer {

    public static void main(String[] args) {

    }

    private static final int DEFAULT_PORT = 4242, DEFAULT_BACKLOG = 10;

    public StreamRequestsServer() {
        this(DEFAULT_PORT, DEFAULT_BACKLOG);
    }

    public StreamRequestsServer(int servePort) {
        this(servePort, DEFAULT_BACKLOG);
    }

    private ThreadPoolExecutor threadPoolExecutor;

    public StreamRequestsServer(int servePort, int backlog) {
        threadPoolExecutor = new ThreadPoolExecutor(DEFAULT_BACKLOG, DEFAULT_BACKLOG, 0, TimeUnit.DAYS,
                new LinkedBlockingQueue<>());

        try (ServerSocket server = new ServerSocket(servePort, backlog)) {
            threadPoolExecutor.execute(new ClientRequestHandler(server.accept()));
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static class ClientRequestHandler implements Runnable {

        private Socket clientSocket;

        public ClientRequestHandler(Socket clientSocket) {
            this.clientSocket = clientSocket;
        }

        @Override
        public void run() {
            /* TODO
            handle request:
                1. authenticate client/server, see TLS 3.0 handshake
                2. present stream options to client
                3. validate client selection
                4. select a broadcast address and send that info to the client
                5. wait for client ack and start stream
             */
        }
    }

}
