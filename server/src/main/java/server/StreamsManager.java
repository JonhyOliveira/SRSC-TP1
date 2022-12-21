package server;

import java.io.InputStream;
import java.util.List;

public interface StreamsManager {

    List<String> getAvailableStreams();

    InputStream getStream(String streamName);

}
