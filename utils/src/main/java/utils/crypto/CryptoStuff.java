package utils.crypto;

import utils.XMLConfigReader;

import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Properties;

public class CryptoStuff
{

    public static class CryptoInstance
    {
        private Cipher cipher;
        private Mac hMac;
        private MessageDigest digest;

        /**
         * Implements a
         * @param mode either encrypt (1) or decrypt (2)
         * @param cryptoProperties defines properties
         */
        public CryptoInstance(int mode, Properties cryptoProperties) throws CryptoException {
            // init
            try {
                String cyphersuite = cryptoProperties.getProperty("ciphersuite");

                AlgorithmParameterSpec ivSpec = null;

                if (cryptoProperties.containsKey("iv"))
                    ivSpec = new IvParameterSpec(parseStringBytes(cryptoProperties.getProperty("iv")));

                if (cryptoProperties.containsKey("integrity")) {
                    String integrityCheck = cryptoProperties.getProperty("integrity");
                    if (cryptoProperties.containsKey("mackey")) {
                        hMac = Mac.getInstance(integrityCheck);
                        hMac.init(new SecretKeySpec(parseStringBytes(cryptoProperties.getProperty("mackey")), integrityCheck));
                    } else
                        digest = MessageDigest.getInstance(integrityCheck);
                }

                Key secretKey = new SecretKeySpec(parseStringBytes(cryptoProperties.getProperty("key")), cyphersuite.split("/")[0]);
                cipher = Cipher.getInstance(cyphersuite);
                cipher.init(mode, secretKey, ivSpec);

            } catch (InvalidAlgorithmParameterException | InvalidKeyException | NoSuchPaddingException |
                     NoSuchAlgorithmException e) {
                throw new CryptoException(e.getMessage(), e);
            }
        }

        public synchronized byte[] compose(InputStream input) throws IOException, CryptoException {
            byte[] in = input.readAllBytes();

            // calculate final plain text length
            int oTLength = in.length;
            if (hMac != null)
                oTLength += hMac.getMacLength();
            else if (digest != null)
                oTLength += digest.getDigestLength();

            // allocate cipher text
            byte[] transformed = new byte[cipher.getOutputSize(oTLength)];

            // encrypt input
            try {
                if (hMac != null || digest != null) { // include integrity check, if needed
                    int currentTTLength = cipher.update(in, 0, in.length, transformed, 0);

                    // encrypt integrity check
                    if (hMac != null) {
                        hMac.update(in);
                        cipher.doFinal(hMac.doFinal(), 0, hMac.getMacLength(), transformed, currentTTLength);
                    } else if (digest != null) {
                        digest.update(in);
                        cipher.doFinal(digest.digest(), 0, digest.getDigestLength(), transformed, currentTTLength);
                    }
                } else
                    cipher.doFinal(transformed, 0);
            } catch (IllegalBlockSizeException | BadPaddingException | ShortBufferException e) {
                throw new CryptoException(e.getMessage(), e);
            }
            return transformed;
        }

        public synchronized byte[] decompose(InputStream input) throws IOException, CryptoException {
            byte[] in = input.readAllBytes();

            try {
                byte[] transformed = cipher.doFinal(in);
                int messageLength = transformed.length;
                // integrity check, if needed
                if (hMac != null || digest != null)
                {
                    byte[] expected = null, actual = null; // integrity checks

                    if (hMac != null)
                    {
                        messageLength = transformed.length - hMac.getMacLength();

                        expected = new byte[hMac.getMacLength()];
                        System.arraycopy(transformed, messageLength, expected, 0, hMac.getMacLength());
                        hMac.update(transformed, 0, messageLength);
                        actual = hMac.doFinal();
                    } else if (digest != null) {
                        messageLength = transformed.length - digest.getDigestLength();

                        expected = new byte[digest.getDigestLength()];
                        System.arraycopy(transformed, messageLength, expected, 0, digest.getDigestLength());
                        digest.update(transformed, 0, messageLength);
                        actual = digest.digest();
                    }

                    if (!MessageDigest.isEqual(actual, expected))
                        throw new CryptoException("Integrity check failed", null);
                }

                if (messageLength == transformed.length)
                    return transformed;
                else {
                    byte[] message = new byte[messageLength];
                    System.arraycopy(transformed, 0, message, 0, messageLength);
                    return message;
                }
            } catch (IllegalBlockSizeException | BadPaddingException e) {
                throw new CryptoException(e.getMessage(), e);
            }
        }
    }

    public static void decrypt(Properties properties, InputStream inputStream, OutputStream outputStream)
            throws CryptoException {
        doCrypto(Cipher.DECRYPT_MODE, properties, inputStream, outputStream);
    }

    public static void decrypt(Properties properties, File inputFile, File outputFile)
            throws CryptoException, FileNotFoundException {
        decrypt(properties, new FileInputStream(inputFile), new FileOutputStream(outputFile));
    }

    public static byte[] decrypt(Properties properties, InputStream inputStream) throws CryptoException
    {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        decrypt(properties, inputStream, baos);

        return baos.toByteArray();
    }

    public static byte[] decrypt(Properties properties, byte[] bytes) throws CryptoException
    {
        return decrypt(properties, new ByteArrayInputStream(bytes));
    }

    public static void encrypt(Properties properties, InputStream inputStream, OutputStream outputStream)
            throws CryptoException {
        doCrypto(Cipher.ENCRYPT_MODE, properties, inputStream, outputStream);
    }

    public static void encrypt(File inputFile, File outputFile, Properties properties)
            throws CryptoException, FileNotFoundException {
        encrypt(properties, new FileInputStream(inputFile), new FileOutputStream(outputFile));
    }

    public static byte[] encrypt(Properties cryptoProperties, InputStream inputStream) throws CryptoException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        encrypt(cryptoProperties, inputStream, baos);

        return baos.toByteArray();
    }

    public static byte[] encrypt(Properties properties, byte[] bytes) throws CryptoException
    {
        return encrypt(properties, new ByteArrayInputStream(bytes));
    }

    private static void doCrypto(int cipherMode, Properties properties, InputStream inputStream,
                                 OutputStream outputStream) throws CryptoException
    {
        try
        {
            // init
            String cyphersuite = properties.getProperty("ciphersuite");

            AlgorithmParameterSpec ivSpec = null; // TODO see other values this can take

            if (properties.getProperty("iv") != null)
                ivSpec = new IvParameterSpec(parseStringBytes(properties.getProperty("iv")));

            Key secretKey = new SecretKeySpec(parseStringBytes(properties.getProperty("key")), cyphersuite.split("/")[0]);
            Cipher cipher = Cipher.getInstance(cyphersuite);
            cipher.init(cipherMode, secretKey, ivSpec);

            // do stuff
            byte[] inputBytes = inputStream.readAllBytes();
            byte[] outputBytes = cipher.doFinal(inputBytes);
            outputStream.write(outputBytes);

            inputStream.close();
            outputStream.close();
        }
        catch (NoSuchPaddingException | NoSuchAlgorithmException
               | InvalidKeyException | BadPaddingException
               | IllegalBlockSizeException
               | InvalidAlgorithmParameterException
               | IOException ex)
        {
            throw new CryptoException("Error encrypting/decrypting", ex);
        }
    }

    private static byte[] parseStringBytes(String s)
    {
        try {
            return HexFormat.of().parseHex(s);
        }
        catch (IllegalArgumentException e)
        {
            return s.getBytes();
        }
    }

    /**
     * Utility to encrypt or decrypt files based on a configuration file
     * @param args [ configuration file, input file, output file, mode: E/D ]
     * @throws IOException if there was an error reading from one of the files
     * @throws CryptoException if there was an error encrypting or decrypting
     */
    public static void main(String[] args) throws IOException, CryptoException {

        enum Mode { E, D }

        System.out.println();

        if (args.length != 4)
        {
            System.out.printf("Correct usage: %s <config file> <input file> <output file> <mode: E/D>\n", CryptoStuff.class.getCanonicalName());
            return;
        }

        Properties cryptoProperties = new Properties();

        try {
            File outFile = new File(args[2]);
            Mode m = Mode.valueOf(args[3]);

            InputStream fcs = new FileInputStream(args[0]);
            InputStream fis = new FileInputStream(args[1]);
            OutputStream fos = new FileOutputStream(outFile);

            cryptoProperties.load(new XMLConfigReader(fcs, outFile.getName()));

            doCrypto(m.ordinal() + 1, cryptoProperties, fis, fos);
            System.out.println("Done!");
        }
        catch (IllegalArgumentException e)
        {
            System.out.println("Invalid mode. Must be either [E]ncrypt or [D]ecrypt.");
        }
        catch (FileNotFoundException e)
        {
            System.out.println(e.getMessage());
            e.printStackTrace();
        }
    }
}
