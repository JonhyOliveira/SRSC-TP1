package utils;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;

public class LengthPreappendInputStream extends InputStream {

    private DataInputStream inputStream;

    public LengthPreappendInputStream(InputStream inputStream) {
        this.inputStream = new DataInputStream(inputStream);
    }

    @Override
    public int read() throws IOException {
        return inputStream.read();
    }

    @Override
    public byte[] readAllBytes() throws IOException {
        int length = inputStream.readInt();
        return super.readNBytes(length);
    }

}
