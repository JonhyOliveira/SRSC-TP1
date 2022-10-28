package utils.crypto; /**
 ** A utility class that encrypts or decrypts a file.
 ** Version 2
 **/


// This is version 2 of CryptoStuff class (ex 3, Lab 1)
// In this version we separate the definition of ALGORITHM
// and the definition of CIPHERSUITE parameterization to be
// more clear and correct the utilization and generalization of
// use ...

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Objects;
import java.util.Properties;


public class CryptoStuff
{

    //For use in your TP1 implementation you must have the crytoconfigs
    //according to the StreamingServer crypto configs
    //because thsi is just an illustrative example with specific
    // defifined configurations.... Reember that for TP1 you
    // must have your own tool to encrypt the movie files that can
    // be used by your StreamingServer implementation

    private static final String ALGORITHM = "AES";
    private static final String TRANSFORMATION = "AES/CTR/PKCS5Padding";
    // See this according to the configuration of StreamingServer
    // Initializaton vector ... See this according to the cryptoconfig
    // of Streaming Server
    private static final byte[] ivBytes  = new byte[]
            {
                    0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01, 0x00 ,
                    0x0f, 0x0d, 0x0e, 0x0c, 0x0b, 0x0a, 0x09, 0x08
            };


    public static void encrypt(File inputFile, File outputFile, Properties properties)
            throws CryptoException, FileNotFoundException {
        doCrypto(Cipher.ENCRYPT_MODE, properties, new FileInputStream(inputFile), new FileOutputStream(outputFile));
    }

    public static void decrypt(Properties properties, File inputFile, File outputFile)
            throws CryptoException, FileNotFoundException {
        doCrypto(Cipher.DECRYPT_MODE, properties, new FileInputStream(inputFile), new FileOutputStream(outputFile));
    }

    public static void encrypt(Properties properties, InputStream inputStream, OutputStream outputStream)
            throws CryptoException {
        doCrypto(Cipher.ENCRYPT_MODE, properties, inputStream, outputStream);
    }

    public static void decrypt(Properties properties, InputStream inputStream, OutputStream outputStream)
            throws CryptoException {
        doCrypto(Cipher.DECRYPT_MODE, properties, inputStream, outputStream);
    }

    public static byte[] decrypt(Properties properties, byte[] bytes) throws CryptoException
    {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        doCrypto(Cipher.DECRYPT_MODE, properties, new ByteArrayInputStream(bytes), baos);

        return baos.toByteArray();
    }

    public static byte[] encrypt(Properties properties, byte[] bytes) throws CryptoException
    {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();

        doCrypto(Cipher.ENCRYPT_MODE, properties, new ByteArrayInputStream(bytes), baos);

        return baos.toByteArray();
    }

    private static void doCrypto(int cipherMode, Properties properties, InputStream inputStream,
                                 OutputStream outputStream) throws CryptoException
    {
        try
        {
            String cyphersuite = properties.getProperty("ciphersuite");

            AlgorithmParameterSpec ivSpec = null; // TODO see other values this can take

            if (properties.getProperty("key") != null)
                ivSpec = new IvParameterSpec(properties.getProperty("iv").getBytes());

            Key secretKey = new SecretKeySpec(properties.getProperty("key").getBytes(), cyphersuite.split("/")[0]);
            Cipher cipher = Cipher.getInstance(cyphersuite);
            cipher.init(cipherMode, secretKey, ivSpec);

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

}
