package srsc.fct.unl.pt;

import box.hjBox;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import server.hjStreamServer;
import utils.crypto.CryptoException;
import utils.crypto.CryptoStuff;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import java.io.*;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.UnknownHostException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.*;

public class Main {
    private static final List<String> modes = List.of("GCM", "CTR", "CCM", "OFB", "CFM", "ECB"),
            integrityChecks = List.of("SHA-1", "SHA256", "SHA512"),
            integrityAuthChecks = List.of("HmacSHA256", "HmacSHA512", "HmacMD5"),
            paddings = List.of("NoPadding", "PKCS5#Padding", "PKCS7#Padding"),
            soloModes = List.of("CHACHA20");

    private static final Map<String, List<Integer>> algoToKeysizes = Map.of(
            "AES", List.of(128, 256, 192), "RC6", List.of(128), "BLOWFISH", List.of(64, 127, 256, 448)
    );

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static void main(String[] args) throws NoSuchAlgorithmException {

        Properties properties;

        for (String algo : algoToKeysizes.keySet())
        {
            var kg = KeyGenerator.getInstance(algo);

            for (Integer keySize : algoToKeysizes.get(algo)) {
                kg.init(keySize);
                SecretKey key = kg.generateKey();

                for (String mode : modes) {
                    for (String padding : paddings) {
                        properties = new Properties();

                        try {
                            String ciphersuite = "%s/%s/%s".formatted(algo, mode, padding);
                            byte[] iv = new byte[Cipher.getInstance(ciphersuite).getBlockSize()];
                            new Random().nextBytes(iv);

                            properties.setProperty("ciphersuite", ciphersuite);
                            properties.setProperty("key", HexFormat.of().formatHex(key.getEncoded()));
                            if (!mode.equals("ECB"))
                                properties.setProperty("iv", HexFormat.of().formatHex(iv));

                            runTest(properties);

                            for (String integrityCheck : integrityChecks) {
                                properties.setProperty("integrity", integrityCheck);
                                runTest(properties);
                            }

                            for (String macCheck : integrityAuthChecks) {
                                properties.setProperty("integrity", macCheck);
                                properties.setProperty("mackey", properties.getProperty("key"));
                                runTest(properties);
                            }
                        } catch (Exception e) {
                            System.out.println(e.getMessage());
                        }
                    }
                }
            }
        }
    }

    private static final InetSocketAddress addr;

    static {
        try {
            addr = new InetSocketAddress(InetAddress.getLocalHost(), 9999);
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        }
    }

    public static void runTest(Properties cryptoProperties) {
        System.out.printf("Testing %s (%d bits)", cryptoProperties.getProperty("ciphersuite"),
                CryptoStuff.parseStringBytes(cryptoProperties.getProperty("key")).length * 8);
        if (cryptoProperties.containsKey("integrity"))
            System.out.printf(" with %s", cryptoProperties.getProperty("integrity"));
        System.out.println(".");

        System.setOut(new PrintStream(new OutputStream() {
            @Override
            public void write(int b) throws IOException {
                // suppress stdout
            }
        }));

        Thread box = new Thread(() -> {
            try {
                hjBox.broadcast(cryptoProperties, addr, Collections.emptySet());
            } catch (IOException | CryptoException e) {
                System.err.println(e.getMessage());
            }
        }),
                server = new Thread(() -> {
                    try {
                        hjStreamServer.broadcastStream("cars",
                                new DataInputStream(new FileInputStream("movies/cars.dat")), addr, cryptoProperties);
                    } catch (IOException | InterruptedException | CryptoException e) {
                        System.err.println(e.getMessage());
                    }
                });

        try {
            box.start();
            Thread.sleep(500);
            server.start();

            box.setUncaughtExceptionHandler((t, e) -> server.interrupt());
            server.setUncaughtExceptionHandler((t, e) -> box.interrupt());
            box.join();
            server.join();
        } catch (InterruptedException e) {
            System.err.println("FAILED");
        } finally {
            // restore output
            System.setOut(new PrintStream(new FileOutputStream(FileDescriptor.out)));
        }
    }
}