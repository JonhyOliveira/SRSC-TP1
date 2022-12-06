package utils.crypto;

import org.bouncycastle.crypto.macs.CMac;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import utils.XMLConfigReader;

import javax.crypto.*;
import javax.crypto.spec.*;
import java.io.*;
import java.security.*;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.InvalidParameterSpecException;
import java.util.*;

public class CryptoStuff
{
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static class CryptoInstance
    {
        private final Cipher cipher;
        private final SecretKey secretKey;
        private AlgorithmParameterSpec keyParameterSpec;
        private Mac hMac;
        private MessageDigest digest;
        private final int mode;

        /**
         * Implements a
         * @param mode either encrypt (1) or decrypt (2), see Cipher.ENCRYPT/DECRYPT
         * @param cryptoProperties defines properties
         */
        public CryptoInstance(int mode, Properties cryptoProperties) throws CryptoException {
            this.mode = mode;
            try {
                String ciphersuite = cryptoProperties.getProperty("ciphersuite");

                if (cryptoProperties.containsKey("integrity")) {
                    String integrityCheck = cryptoProperties.getProperty("integrity");
                    if (cryptoProperties.containsKey("mackey")) {
                        hMac = Mac.getInstance(integrityCheck);
                        hMac.init(new SecretKeySpec(parseStringBytes(cryptoProperties.getProperty("mackey")), integrityCheck));
                    } else
                        digest = MessageDigest.getInstance(integrityCheck);
                }

                if (cryptoProperties.containsKey("iv"))
                    keyParameterSpec = new IvParameterSpec(parseStringBytes(cryptoProperties.getProperty("iv")));
                /* NOT WORKING :( else if (cryptoProperties.containsKey("nonce"))
                    keyParameterSpec = new ChaCha20ParameterSpec(parseStringBytes(cryptoProperties.getProperty("nounce")),
                            parseStringBytes(cryptoProperties.getProperty("counter"))[0]); */
                if (cryptoProperties.containsKey("password"))
                    keyParameterSpec = new PBEParameterSpec(parseStringBytes(cryptoProperties.getProperty("salt")),
                            100, keyParameterSpec);


                if (cryptoProperties.containsKey("key"))
                    secretKey = new SecretKeySpec(parseStringBytes(cryptoProperties.getProperty("key")), ciphersuite.split("/")[0]);
                else if (cryptoProperties.containsKey("password"))
                    secretKey = SecretKeyFactory.getInstance(cryptoProperties.getProperty("ciphersuite"))
                            .generateSecret(new PBEKeySpec(cryptoProperties.getProperty("password").toCharArray()));
                else
                    secretKey = null;

                cipher = Cipher.getInstance(ciphersuite);
                cipher.init(this.mode, secretKey, keyParameterSpec);

            } catch (InvalidAlgorithmParameterException | InvalidKeyException | NoSuchPaddingException |
                     NoSuchAlgorithmException | InvalidKeySpecException e) {
                throw new CryptoException(e.getMessage(), e);
            }
        }

        public synchronized byte[] transform(InputStream input) throws IOException, CryptoException {
            /* NOT WORKING :( if (keyParameterSpec instanceof ChaCha20ParameterSpec) {
                try {
                    keyParameterSpec = new ChaCha20ParameterSpec(((ChaCha20ParameterSpec) keyParameterSpec).getNonce(),
                            ((ChaCha20ParameterSpec) keyParameterSpec).getCounter() + 1);
                    cipher.init(mode, secretKey, keyParameterSpec);
                } catch (InvalidAlgorithmParameterException | InvalidKeyException e) {
                    throw new CryptoException(e.getMessage(), e);
                }
            }*/

            if (mode == Cipher.ENCRYPT_MODE)
                return compose(input);
            else if (mode == Cipher.DECRYPT_MODE)
                return decompose(input, null);
            else
                return null;
        }

        private synchronized byte[] compose(InputStream input) throws IOException, CryptoException {
            byte[] in = input.readAllBytes();

            ByteArrayOutputStream cipherTextBaos = new ByteArrayOutputStream(cipher.getOutputSize(in.length));
            ByteArrayOutputStream plainTextBaos = new ByteArrayOutputStream(in.length);
            plainTextBaos.write(in);

            // encrypt input
            try {
                if (hMac != null || digest != null) { // include integrity check, if needed
                    // encrypt integrity check
                    if (hMac != null) {
                        plainTextBaos.write(hMac.doFinal(in));
                    } else {
                        plainTextBaos.write(digest.digest(in));
                    }
                }
                cipherTextBaos.write(cipher.doFinal( plainTextBaos.toByteArray()));
            } catch (IllegalBlockSizeException | BadPaddingException e) {
                throw new CryptoException(e.getMessage(), e);
            }
            return cipherTextBaos.toByteArray();
        }

        private synchronized byte[] decompose(InputStream input, byte[] integrityCheck) throws IOException, CryptoException {
            byte[] in = input.readAllBytes();

            ByteArrayOutputStream clearTextBaos = new ByteArrayOutputStream();

            try {
                byte[] transformed = cipher.doFinal(in);
                int messageLength = transformed.length;
                // integrity check, if needed
                if (hMac != null || digest != null)
                {
                    byte[] actual, expected;

                    if (integrityCheck == null) {
                        if (hMac != null) {
                            messageLength = transformed.length - hMac.getMacLength();
                            hMac.update(transformed, 0, messageLength);
                            actual = hMac.doFinal();
                        } else {
                            messageLength = transformed.length - digest.getDigestLength();
                            digest.update(transformed, 0, messageLength);
                            actual = digest.digest();
                        }
                        expected = new byte[transformed.length - messageLength];
                        System.arraycopy(transformed, messageLength, expected, 0, transformed.length - messageLength);
                    }
                    else {
                        expected = integrityCheck;
                        if (hMac != null)
                            actual = hMac.doFinal(transformed);
                        else
                            actual = digest.digest(transformed);
                    }
                    if (!MessageDigest.isEqual(actual, expected))
                        throw new CryptoException("Integrity check failed", null);
                }
                else if (integrityCheck != null && integrityCheck.length > 0)
                    throw new CryptoException("Integrity check failed", null);
                clearTextBaos.write(transformed, 0, messageLength);
                return clearTextBaos.toByteArray();
            } catch (IllegalBlockSizeException | BadPaddingException e) {
                throw new CryptoException(e.getMessage(), e);
            }
        }
    }

    public static void decrypt(Properties properties, InputStream inputStream, OutputStream outputStream)
            throws CryptoException {

        try
        {
            byte[] integrityCheck = null;
            if (properties.contains("integrity-check"))
                integrityCheck = parseStringBytes(properties.getProperty("integrity-check"));
            outputStream.write(new CryptoInstance(Cipher.DECRYPT_MODE, properties).decompose(inputStream, integrityCheck));

            inputStream.close();
            outputStream.close();
        }
        catch (IOException ex)
        {
            throw new CryptoException("Error encrypting/decrypting", ex);
        }
    }

    public static void decrypt(Properties properties, File inputFile, File outputFile)
            throws CryptoException, FileNotFoundException {
        decrypt(properties, new FileInputStream(inputFile), new FileOutputStream(outputFile));
    }

    public static void encrypt(Properties properties, InputStream inputStream, OutputStream outputStream)
            throws CryptoException {

        try
        {
            outputStream.write(new CryptoInstance(Cipher.ENCRYPT_MODE, properties).compose(inputStream));

            inputStream.close();
            outputStream.close();
        }
        catch (IOException ex)
        {
            throw new CryptoException("Error encrypting/decrypting", ex);
        }
    }

    public static byte[] parseStringBytes(String s)
    {
        byte[] bytes;
        try {
            bytes = HexFormat.of().parseHex(s);
        }
        catch (IllegalArgumentException e)
        {
            bytes = s.getBytes();
        }
        // System.out.println(bytes.length);
        return bytes;
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
            cryptoProperties.stringPropertyNames().stream()
                            .forEach(s -> {
                                if (cryptoProperties.getProperty(s).equalsIgnoreCase("NULL"))
                                    cryptoProperties.remove(s);
                            });

            cryptoProperties.stringPropertyNames()
                    .forEach(p -> System.out.printf("%-20s -> '%s'\n", p, cryptoProperties.getProperty(p)));

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

    private static void doCrypto(int i, Properties cryptoProperties, InputStream fis, OutputStream fos)
            throws CryptoException {
        if (i == Cipher.ENCRYPT_MODE)
            encrypt(cryptoProperties, fis, fos);
        else if (i == Cipher.DECRYPT_MODE)
            decrypt(cryptoProperties, fis, fos);
    }


}
