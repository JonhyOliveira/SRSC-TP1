package server;

import java.net.SocketAddress;

public interface StreamingServer {
    int stream(StreamInfo info);

    SocketAddress getBroadcastAddr();
}
