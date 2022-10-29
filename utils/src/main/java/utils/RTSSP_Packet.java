package utils;

import java.io.DataInputStream;
import java.net.DatagramPacket;
import java.rmi.UnexpectedException;

public class RTSSP_Packet {

    public enum Type { NULL, START, END, DATA; }

    public static final int BUFFER_SIZE = 4096;

    /**
     * Composes a packet inside a datagram packet
     * @param packetType the type of the packet
     * @param metadata the packet metadata
     * @param dest where to write the packet data to
     */
    public static void compose(RTSSP_Packet.Type packetType, byte[] metadata, DatagramPacket dest)
    {
        dest.getData()[0] = ((byte) packetType.ordinal());
        System.arraycopy(metadata, 0, dest.getData(), 1, metadata.length);
        dest.setLength(metadata.length + 1);
    }

    /**
     * Copies the packet metadata to a byte array
     * @param packetData the packet data
     * @param dest where to write the packet metadata to
     */
    public static void copyPacketMetadata(byte[] packetData, byte[] dest)
    {
        if (packetData.length == 0)
            return;
        System.arraycopy(packetData, 1, dest, 0, packetData.length - 1);
    }

    /**
     * @param packetData the packet data
     * @return the packet metdata
     */
    public static byte[] getPacketData(byte[] packetData)
    {
        if (packetData.length == 0)
            return new byte[0];

        byte[] metadata = new byte[Math.max(packetData.length - 1, 0)];
        copyPacketMetadata(packetData, metadata);

        return metadata;
    }

    /**
     * @param packetData the packet data
     * @return the packet type
     * @throws UnexpectedException if the packet type is invalid
     */
    public static RTSSP_Packet.Type getPacketType(byte[] packetData) throws UnexpectedException {
        if (packetData[0] < RTSSP_Packet.Type.values().length && packetData[0] > 0)
            return RTSSP_Packet.Type.values()[packetData[0]];
        return RTSSP_Packet.Type.NULL;
    }

}
