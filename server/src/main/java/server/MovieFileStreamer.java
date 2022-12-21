package server;

import java.io.*;
import java.util.Arrays;
import java.util.List;

public class MovieFileStreamer implements StreamsManager {

    private File directory;
    private String fileExtension;

    public MovieFileStreamer(File movieDirectory, String extension) {

        if (!(movieDirectory.exists() && movieDirectory.isDirectory()))
            throw new IllegalArgumentException("Provided argument must be an existing directory");

        directory = movieDirectory;
        fileExtension = extension;
    }

    @Override
    public List<String> getAvailableStreams() {
        return Arrays.stream(directory.listFiles((dir, name) -> name.matches("^[0-9a-zA-Z-_]+."+ fileExtension +"$")))
                .map(File::getName)
                .map(s -> s.split("\\.")[0])
                .toList();
    }

    @Override
    public InputStream getStream(String streamName) {
        try {
            return new FileInputStream(new File(directory, "%s.film".formatted(streamName)));
        } catch (FileNotFoundException e) {
            return null;
        }
    }
}
