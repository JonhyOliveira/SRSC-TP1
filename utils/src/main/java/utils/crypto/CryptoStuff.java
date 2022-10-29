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
        public CryptoInstance(int mode, Properties cryptoProperties)
                throws InvalidAlgorithmParameterException, InvalidKeyException,
                NoSuchPaddingException, NoSuchAlgorithmException {
            // init
            String cyphersuite = cryptoProperties.getProperty("ciphersuite");

            AlgorithmParameterSpec ivSpec = null;

            if (cryptoProperties.containsKey("iv"))
                ivSpec = new IvParameterSpec(parseStringBytes(cryptoProperties.getProperty("iv")));

            if (cryptoProperties.containsKey("integrity"))
            {
                String integrityCheck = cryptoProperties.getProperty("integrity");
                if (cryptoProperties.containsKey("mackey"))
                {
                    hMac = Mac.getInstance(integrityCheck);
                    hMac.init(new SecretKeySpec(parseStringBytes(cryptoProperties.getProperty("mackey")), integrityCheck));
                }
                else
                    digest = MessageDigest.getInstance(integrityCheck);
            }

            Key secretKey = new SecretKeySpec(parseStringBytes(cryptoProperties.getProperty("key")), cyphersuite.split("/")[0]);
            cipher = Cipher.getInstance(cyphersuite);
            cipher.init(mode, secretKey, ivSpec);
        }

        public synchronized byte[] finish(InputStream input) throws IOException, CryptoException {
            byte[] in = input.readAllBytes();

            // calculate final plain text length
            int pTLength = in.length;
            if (hMac != null)
                pTLength += hMac.getMacLength();
            else if (digest != null)
                pTLength += digest.getDigestLength();

            // allocate cipher text
            byte[] cipherText = new byte[cipher.getOutputSize(pTLength)];

            // encrypt input
            try {
                if (hMac != null || digest != null) {
                    int currentCTLength = cipher.update(in, 0, in.length, cipherText, 0);

                    // encrypt integrity check
                    if (hMac != null) {
                        hMac.update(in);
                        cipher.doFinal(hMac.doFinal(), 0, hMac.getMacLength(), cipherText, currentCTLength);
                    } else if (digest != null) {
                        digest.update(in);
                        cipher.doFinal(digest.digest(), 0, digest.getDigestLength(), cipherText, currentCTLength);
                    }
                } else
                    cipher.doFinal(cipherText, 0);
            } catch (IllegalBlockSizeException | BadPaddingException | ShortBufferException e) {
                throw new CryptoException(e.getMessage(), e);
            }
            return cipherText;
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
