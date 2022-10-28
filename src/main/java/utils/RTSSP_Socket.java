package utils;

import utils.crypto.CryptoException;
import utils.crypto.CryptoStuff;

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.util.Properties;

public class RTSSP_Socket extends DatagramSocket {

    private Properties cryptoProperties;

    public RTSSP_Socket(Properties cryptoProperties) throws SocketException {
        super();
        this.cryptoProperties = cryptoProperties;
    }

    public RTSSP_Socket(Properties cryptoProperties, SocketAddress bindaddr) throws SocketException {
        super(bindaddr);
        this.cryptoProperties = cryptoProperties;
    }

    @Override
    public void send(DatagramPacket p) throws IOException {
        byte[] encrypted = new byte[0];
        try {
            encrypted = CryptoStuff.encrypt(cryptoProperties, p.getData());
        } catch (CryptoException e) {
            throw new RuntimeException(e);
        }
        DatagramPacket encryptedPacket = new DatagramPacket(encrypted, encrypted.length, p.getSocketAddress());
        super.send(encryptedPacket);
    }

    @Override
    public void receive(DatagramPacket p) throws IOException {
        super.receive(p);
        byte[] decrypted = new byte[0];
        try {
            decrypted = CryptoStuff.decrypt(cryptoProperties, p.getData());
        } catch (CryptoException e) {
            throw new RuntimeException(e);
        }

        System.arraycopy(decrypted, 0, p.getData(), 0, decrypted.length);
        p.setLength(decrypted.length);
    }
}
