package utils;

import utils.crypto.CryptoException;
import utils.crypto.CryptoStuff;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Properties;

public class RTSSP_Socket extends DatagramSocket {

    private CryptoStuff.CryptoInstance cryptoInstance;

    public RTSSP_Socket(Properties cryptoProperties) throws SocketException, CryptoException {
        super();
        init(Cipher.ENCRYPT_MODE, cryptoProperties);
    }

    public RTSSP_Socket(Properties cryptoProperties, SocketAddress bindaddr) throws SocketException, CryptoException {
        super(bindaddr);
        init(Cipher.DECRYPT_MODE, cryptoProperties);
    }

    private void init(int cipherMode, Properties cryptoProperties) throws CryptoException {
        this.cryptoInstance = new CryptoStuff.CryptoInstance(cipherMode, cryptoProperties);
    }

    /**
     * Encrypts and send a packet
     * @param p   the {@code DatagramPacket} to be sent.
     *
     * @throws IOException if an I/O error occurs
     */
    @Override
    public void send(DatagramPacket p) throws IOException {
        byte[] encrypted = new byte[0];

        try {
            encrypted = cryptoInstance.compose(new ByteArrayInputStream(p.getData(), 0, p.getLength()));
        } catch (CryptoException e) {
            throw new RuntimeException(e);
        }
        DatagramPacket encryptedPacket = new DatagramPacket(encrypted, encrypted.length, p.getSocketAddress());
        super.send(encryptedPacket);
    }

    /**
     * Decrypts and sends a packet
     * @param p   the {@code DatagramPacket} into which to place
     *                 the incoming data.
     * @throws IOException
     */
    @Override
    public void receive(DatagramPacket p) throws IOException {
        super.receive(p);
        byte[] decrypted = new byte[0];
        try {
            decrypted = cryptoInstance.decompose(new ByteArrayInputStream(p.getData(), 0, p.getLength()));
        } catch (CryptoException e) {
            throw new RuntimeException(e);
        }

        System.arraycopy(decrypted, 0, p.getData(), 0, decrypted.length);
        p.setLength(decrypted.length);
    }
}
