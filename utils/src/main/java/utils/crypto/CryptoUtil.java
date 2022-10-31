package utils.crypto;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import java.io.File;
import java.security.Key;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

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
