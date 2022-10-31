package utils;

import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.io.Reader;
import java.util.Properties;

import static org.junit.jupiter.api.Assertions.*;

class ConfigReaderTest {

    @Test
    void works() throws IOException {

        InputStream is = this.getClass().getClassLoader().getResourceAsStream("server_configs/box-cryptoconfig");

        try (Reader r = new XMLConfigReader(is, "127.0.0.1:9999"))
        {
            Properties movieProps = new Properties();
            movieProps.load(r);

            assertNotNull(movieProps.get("key"));
            movieProps.stringPropertyNames().forEach(s -> { System.out.printf("%-20s -> %s\n", s, movieProps.getProperty(s)); });
        }

    }


}