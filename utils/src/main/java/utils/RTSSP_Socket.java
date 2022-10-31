package utils;

import utils.crypto.CryptoException;
import utils.crypto.CryptoStuff;

import javax.crypto.Cipher;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.util.Properties;

public class RTSSP_Socket {

    private CryptoStuff.CryptoInstance cryptoInstance;
    private final DatagramSocket socket;
    private Telemetry telemetry;

    public RTSSP_Socket(Properties cryptoProperties) throws SocketException, CryptoException {
        socket = new DatagramSocket();
        init(Cipher.ENCRYPT_MODE, cryptoProperties);
    }

    public RTSSP_Socket(Properties cryptoProperties, SocketAddress bindaddr) throws SocketException, CryptoException {
        socket = new DatagramSocket(bindaddr);
        init(Cipher.DECRYPT_MODE, cryptoProperties);
    }

    private void init(int cipherMode, Properties cryptoProperties) throws CryptoException {
        this.cryptoInstance = new CryptoStuff.CryptoInstance(cipherMode, cryptoProperties);
    }

    public void telemetrize(Telemetry telemetry)
    {
        this.telemetry = telemetry;
    }

    /**
     * Encrypts and send a packet
     * @param data   the {@code data} to be sent.
     *
     * @throws IOException if an I/O error occurs
     */
    public void send(byte[] data, SocketAddress addr) throws IOException {
        byte[] encrypted = new byte[0];

        try {
            encrypted = cryptoInstance.transform(new ByteArrayInputStream(data, 0, data.length));
        } catch (CryptoException e) {
            throw new RuntimeException(e);
        }

        if (this.telemetry != null)
            this.telemetry.recordFrame((long) encrypted.length, (long) data.length);

        //System.out.printf("Sent %d bytes.\n", encrypted.length);
        socket.send(new DatagramPacket(encrypted, encrypted.length, addr));
    }

    /**
     * Decrypts a packet
     * @throws IOException
     */
    public byte[] receive() throws IOException {
        DatagramPacket p = new DatagramPacket(new byte[RTSSP_Packet.BUFFER_SIZE], RTSSP_Packet.BUFFER_SIZE);
        socket.receive(p);

        // System.out.printf("Got %d bytes.\n", p.getLength());

        try {
            byte[] decrypted = cryptoInstance.transform(new ByteArrayInputStream(p.getData(), 0, p.getLength()));

            if (this.telemetry != null)
                this.telemetry.recordFrame((long) p.getLength(), (long) decrypted.length);
            return decrypted;

        } catch (CryptoException e) {
            throw new RuntimeException(e);
        }
    }

}
