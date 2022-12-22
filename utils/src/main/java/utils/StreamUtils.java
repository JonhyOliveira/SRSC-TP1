package utils;

import java.io.*;

public class StreamUtils {

    public static void sendBytes(OutputStream outputStream, byte[] bytes) throws IOException {
        new DataOutputStream(outputStream).writeShort(bytes.length);
        outputStream.write(bytes);
    }

    public static byte[] receiveBytes(InputStream inputStream) throws IOException {
        return inputStream.readNBytes(new DataInputStream(inputStream).readShort());
    }

}
