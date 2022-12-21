package utils.crypto;

import utils.HandshakeException;

import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import java.io.*;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.*;
import java.util.stream.Stream;

public class CryptoUtil {

    private static Map<File, Properties> encryptDir(File dir, boolean recursive, Properties encryptionSettings)
    {
        if (!dir.isDirectory())
            return Map.of();

        Map<File, Properties> fileEncryptionProperties = new HashMap<>();


        for (File file : dir.listFiles())
        {
            if (file.isFile())
            {
                fileEncryptionProperties.put(file, encryptFile(file, encryptionSettings));
            }
            else if (file.isDirectory() && recursive)
                fileEncryptionProperties.putAll(encryptDir(file, true, encryptionSettings));
        }

        return fileEncryptionProperties;
    }

    /**
     * Encrypts a file, returning the properties containing key, iv and integrity checks
     * that should be used to validate the file
     * @param file the file to encrypt
     * @param encryptionSettings specifies how to generate keys and ivs for encryption
     * @return properties specifying decryption settings
     */
    private static Properties encryptFile(File file, Properties encryptionSettings) {
        // TODO
        return null;
    }

}
