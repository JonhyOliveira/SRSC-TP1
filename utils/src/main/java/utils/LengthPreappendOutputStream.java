package utils;

import java.io.DataOutputStream;
import java.io.IOException;
import java.io.OutputStream;

public class LengthPreappendOutputStream<lT> extends OutputStream {

    private DataOutputStream outputStream;
    private Class<lT> type;

    public LengthPreappendOutputStream(OutputStream outputStream, Class<lT> lengthType) {
        this.outputStream = new DataOutputStream(outputStream);
        type = lengthType;
    }

    @Override
    public void write(int b) throws IOException {
        outputStream.write(b);
    }

    @Override
    public void write(byte[] b, int off, int len) throws IOException {
        if (type.equals(Integer.class))
            this.outputStream.writeInt(len);
        else if (type.equals(Short.class))
            this.outputStream.writeShort(len);
        else if (type.equals(Byte.class))
            this.outputStream.write(len);

        super.write(b, off, len);
    }
}
