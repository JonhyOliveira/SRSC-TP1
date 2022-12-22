package utils.crypto;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.HexFormat;
import java.util.Properties;
import java.util.Random;

public enum Ciphersuites {
    DSA_AES_128_GCM_HmacSHA256("DSA", "AES/GCM/NoPadding", 128, 256),
    ECDSA_AES_256_GCM_HmacSHA384("ECDSA", "AES/GCM/NoPadding", 256, 384),
    DSA_AES_128_CTR_HmacSHA256("DSA", "AES/CTR/NoPadding", 128, 256),
    DSA_AES_128_OFB_HmacSHA256("DSA", "AES/OFB/NoPadding", 128, 256),
    ECDSA_AES_128_CTR_HmacSHA256("ECDSA", "AES/CTR/NoPadding", 128, 256);

    private final String signatureAlgo, symmetricCipher;
    private final int keySize, SHASize;

    Ciphersuites(String signatureAlgo, String symmetricCipher, int keySize, int SHASize) {
        this.signatureAlgo = signatureAlgo;
        this.symmetricCipher = symmetricCipher;
        this.keySize = keySize;
        this.SHASize = SHASize;
    }

    public String getSignatureAlgo() {
        return signatureAlgo;
    }

    /**
     * Generates crypto properties for this ciphersuite
     * @param seed the seed used to generate
     * @return the generated crypto properties
     */
    public Properties generateCryptoProperties(byte[] seed) throws CryptoException {
        Properties properties = new Properties();

        properties.setProperty("ciphersuite", this.symmetricCipher);

        byte[] key = Arrays.copyOf(seed, this.keySize / 8);
        try {
            byte[] iv = Arrays.copyOfRange(seed, this.keySize / 8, this.keySize / 8 + 16);
            byte[] HMACKey = MessageDigest.getInstance("SHA512").digest(seed);

            properties.setProperty("iv", HexFormat.of().formatHex(iv));
            properties.setProperty("integrity", "HmacSHA" + this.SHASize);
            properties.setProperty("mackey", HexFormat.of().formatHex(HMACKey));
        } catch (NoSuchAlgorithmException e) {
            throw new CryptoException("Algorithm not found", e);
        }
        properties.setProperty("key", HexFormat.of().formatHex(key));

        return properties;
    }
}
