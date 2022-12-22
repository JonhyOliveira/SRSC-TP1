package utils;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.InputStream;

public class LengthPreappendInputStream<lT> extends InputStream {

    private DataInputStream inputStream;
    private Class<lT> type;

    public LengthPreappendInputStream(InputStream inputStream, Class<lT> lengthType) {
        this.inputStream = new DataInputStream(inputStream);
        type = lengthType;
    }

    @Override
    public int read() throws IOException {
        return inputStream.read();
    }

    @Override
    public byte[] readAllBytes() throws IOException {
        int length = -1;

        if (type.equals(Integer.class))
            length = this.inputStream.readInt();
        else if (type.equals(Short.class))
            length = this.inputStream.readUnsignedShort();
        else if (type.equals(Byte.class))
            length = this.inputStream.readUnsignedByte();

        if (length >= 0)
            return super.readNBytes(length);
        else
            return super.readAllBytes();
    }

}
