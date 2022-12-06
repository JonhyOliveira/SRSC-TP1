package srsc.fct.unl.pt;

import box.Box;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import server.StreamServer;
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

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    private static final List<String> modes = List.of("GCM", "CTR", /*"CCM",*/ "OFB", "CFB", "ECB"),
            integrityChecks = List.of("SHA-1", "SHA256", "SHA512"),
            integrityAuthChecks = List.of("HmacSHA256", "HmacSHA512", "HmacMD5"),
            paddings = List.of("NoPadding", "PKCS5Padding", "PKCS7Padding"),
            soloModes = List.of("CHACHA20");

    private static final Map<String, List<Integer>> algoToKeysizes = Map.of(
            "AES", List.of(128, 256, 192), "RC6", List.of(128), "BLOWFISH", List.of(64, 127, 256, 448)
    );

    private static final List<String> streamAlgos = List.of();

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static <T> T randomChoice(Random random, Collection<T> samplesSet)
    {
        T[] a = (T[]) samplesSet.toArray();

        return a[random.nextInt(a.length)];
    }

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchPaddingException {

        Properties properties;
        Random random = new Random();
        final List<Properties> props = new LinkedList<>();

        String algo = randomChoice(random, algoToKeysizes.keySet());
        Integer keySize = randomChoice(random, algoToKeysizes.get(algo));

        String mode = "CCM"; randomChoice(random, modes);

        String padding = streamAlgos.contains(algo) ? "NoPadding" : mode.equals("ECB") ? "PKCS5Padding" : randomChoice(random, paddings);

        var kg = KeyGenerator.getInstance(algo);
        kg.init(keySize);

        SecretKey key = kg.generateKey();
        String ciphersuite = "%s/%s/%s".formatted(algo, mode, padding);
        byte[] iv = null;
        if (!mode.equals("ECB"))
        {
            iv = new byte[Cipher.getInstance(ciphersuite).getBlockSize()];
            random.nextBytes(iv);
        }

        properties = new Properties();
        properties.setProperty("key", HexFormat.of().formatHex(key.getEncoded()));
        properties.setProperty("ciphersuite", ciphersuite);
        if (iv != null)
            properties.setProperty("iv", HexFormat.of().formatHex(iv));

        double r = random.nextGaussian();
        if (r < 0.4D)
            properties.setProperty("integrity", integrityChecks.get(random.nextInt(integrityChecks.size() - 1)));
        else if (r < 0.9D)
        {
            properties.setProperty("integrity", integrityAuthChecks.get(random.nextInt(integrityAuthChecks.size() - 1)));
            properties.setProperty("mackey", properties.getProperty("key"));
        }

        System.out.println(ciphersuite + " OK");
        runTest(properties);
        /*
        for (String algo : algoToKeysizes.keySet())
        {
            var kg = KeyGenerator.getInstance(algo);

            for (Integer keySize : algoToKeysizes.get(algo)) {
                kg.init(keySize);
                SecretKey key = kg.generateKey();

                for (String mode : modes) {
                    for (String padding : paddings) {
                        properties = new Properties();
                        if (streamAlgos.contains(algo) && !padding.equals("NoPadding"))
                            continue;
                        try {
                            String ciphersuite = "%s/%s/%s".formatted(algo, mode, padding);
                            byte[] iv = new byte[Cipher.getInstance(ciphersuite).getBlockSize()];
                            random.nextBytes(iv);

                            properties.setProperty("ciphersuite", ciphersuite);
                            properties.setProperty("key", HexFormat.of().formatHex(key.getEncoded()));
                            if (!mode.equals("ECB"))
                                properties.setProperty("iv", HexFormat.of().formatHex(iv));

                            var thisProps = new Properties();
                            thisProps.putAll(properties);

                            props.add(thisProps);
                            // runTest(properties);

                            if (random.nextGaussian() > 0.5D)
                                properties.setProperty("integrity", integrityChecks.get(random.nextInt(integrityChecks.size() - 1)));
                            else
                            {
                                properties.setProperty("integrity", integrityAuthChecks.get(random.nextInt(integrityAuthChecks.size() - 1)));
                                properties.setProperty("mackey", properties.getProperty("key"));
                            }
                            thisProps.putAll(properties);

                            props.add(thisProps);
                            /* SLOWER, EXAUSTIVE, METHOD
                            for (String integrityCheck : integrityChecks) {
                                properties.setProperty("integrity", integrityCheck);
                                runTest(properties);
                            }

                            for (String macCheck : integrityAuthChecks) {
                                properties.setProperty("integrity", macCheck);
                                properties.setProperty("mackey", properties.getProperty("key"));
                                runTest(properties);
                            }
                            /
                        } catch (Exception e) {
                            System.out.println(e.getMessage());
                        }
                    }
                }
            }
        }
        */

        props.stream().forEach(p -> {
            System.out.printf("Test %s (%d bits)", p.getProperty("ciphersuite"),
                    CryptoStuff.parseStringBytes(p.getProperty("key")).length * 8);
            if (p.containsKey("integrity"))
                System.out.printf(" with %s", p.getProperty("integrity"));
            System.out.println("?");

            if (new Scanner(System.in).nextBoolean())
                runTest(p);
        });
    }

    private static final InetAddress localhost;

    static {
        try {
            localhost = InetAddress.getLocalHost();
        } catch (UnknownHostException e) {
            throw new RuntimeException(e);
        }
    }

    private static InetSocketAddress addr = new InetSocketAddress(localhost, 5000);

    public static void runTest(Properties cryptoProperties) {
        Properties properties = new Properties();
        properties.putAll(cryptoProperties);
        properties.stringPropertyNames().stream().forEach(s -> System.out.printf("%s -> %s", s, properties.getProperty(s)));

        /*System.setOut(new PrintStream(new OutputStream() {
            @Override
            public void write(int b) throws IOException {
                // suppress stdout
            }
        }));*/

        Thread box, server, timeKeeper;
        ThreadGroup threadGroup = new ThreadGroup("%db-%s".formatted(CryptoStuff.parseStringBytes(properties.getProperty("key")).length * 8,
                properties.getProperty("ciphersuite"))) {
            @Override
            public void uncaughtException(Thread t, Throwable e) {
                // super.uncaughtException(t, e);
                // e.printStackTrace();
                System.err.printf("tg '%s' killed by exception. %s%n", this.getName(), e.getMessage());
                this.stop();
            }
        };
        box = new Thread(threadGroup, () -> {
            try {
                Box.broadcast(properties, addr, Set.of(new InetSocketAddress("224.7.7.7", 7777)));
            } catch (IOException | CryptoException e) {
                System.err.println(e.getMessage());
            }
        });
        /* server = new Thread(threadGroup, () -> {
            try {
                StreamServer.broadcastStream("cars",
                        new DataInputStream(new FileInputStream("movies/cars.dat")), addr, properties);
            } catch (IOException | InterruptedException | CryptoException e) {
                System.err.println(e.getMessage());
            }
        }); */
        /* timeKeeper = new Thread(threadGroup, () -> {
            long t0 = System.currentTimeMillis();
            while (threadGroup.activeCount() > 1)
            {
                /*System.err.printf("%02d threads, running for %.3f seconds\r", threadGroup.activeCount(),
                        (float) (System.currentTimeMillis() - t0) / 1000);/
                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                }
            }

        });
        */

        try {
            // timeKeeper.start();
            box.start();
            Thread.sleep(500);
            /*if (threadGroup.activeCount() >= 1)
                server.start();*/

            box.join();
            // server.join();

        } catch (InterruptedException e) {
            System.err.println("FAILED");
        } finally {
            // restore output
            System.setOut(new PrintStream(new FileOutputStream(FileDescriptor.out)));
            addr = new InetSocketAddress(localhost, addr.getPort() + 1);
        }
    }
}