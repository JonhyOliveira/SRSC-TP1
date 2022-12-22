package utils;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public class LengthPreappendOutputStream extends OutputStream {

    private DataOutputStream outputStream;

    public LengthPreappendOutputStream(OutputStream outputStream) {
        this.outputStream = new DataOutputStream(outputStream);
    }

    @Override
    public void write(int b) throws IOException {
        outputStream.write(b);
    }

    @Override
    public void write(byte[] b) throws IOException {
        this.outputStream.writeInt(b.length);
        super.write(b);
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        this.outputStream.writeInt(len);
        super.write(b, off, len);
    }
}
