package utils.crypto;

import org.junit.jupiter.api.Test;
import utils.ConfigReader;

import java.io.IOException;
import java.util.Properties;

class CryptoStuffTest {

    @Test
    public void encrypt() throws IOException {
        Properties properties = new Properties();
        properties.load(new ConfigReader(this.getClass().getClassLoader()
                .getResourceAsStream("server_configs/movies-cryptoconfig"), "monsters.dat.encrypted"));


    }

}