package utils;

import utils.crypto.CryptoException;
import utils.crypto.CryptoStuff;

import java.io.*;
import java.util.Properties;

public class FileUtils {

    public static InputStream streamFromResourceOrPath(String toResolve) throws FileNotFoundException {
        InputStream fis = FileUtils.class.getClassLoader().getResourceAsStream(toResolve);

        if (fis == null)
            fis = new FileInputStream(toResolve);
        return fis;
    }

}
