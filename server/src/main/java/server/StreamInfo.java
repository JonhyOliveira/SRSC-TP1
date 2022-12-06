package server;

import java.io.DataInputStream;
import java.util.Properties;

public final class StreamInfo {

    private String streamID;
    private DataInputStream streamData;
    private Properties cryptoProperties;
    public StreamInfo(String streamID, DataInputStream stream, Properties streamCryptoProps) {
        this.streamID = streamID;
        this.streamData = stream;
        this.cryptoProperties = new Properties(streamCryptoProps);
    }

    public String getStreamID() {
        return streamID;
    }

    public DataInputStream getStreamData() {
        return streamData;
    }

    public Properties getCryptoProperties() {
        return cryptoProperties;
    }
}
