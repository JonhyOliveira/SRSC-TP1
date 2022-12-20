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

    public static final String CRL_DISTRIBUTION_POINT_OID = "2.5.29.31";

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

    public static KeyAgreement getKeyAgreement(String spec) throws NoSuchAlgorithmException, NoSuchProviderException {

        KeyAgreement keyAgreement;

        String[] specDetails = spec.split(":");
        String[] algoDetails = specDetails[0].split("_");

        if (spec.matches("^[0-9a-zA-Z]+(_[0-9]+)?(:[0-9a-zA-Z]+)?$")) {
            if (specDetails.length == 2)
                keyAgreement = KeyAgreement.getInstance(algoDetails[0], specDetails[1]);
            else
                keyAgreement = KeyAgreement.getInstance(algoDetails[0]);
        }
        else
            throw new IllegalArgumentException("Spec argument '" + spec + "' should be in format: <Algo>[_<KeySize>][:<Provider>]");

        return keyAgreement;
    }

    public static KeyPair generateKeyPair(String spec, String parameters)
            throws InvalidAlgorithmParameterException, NoSuchAlgorithmException, NoSuchProviderException {
        KeyPairGenerator keyGen;
        int keySize = -1;
        String[] specDetails = spec.split(":");
        String[] algoDetails = specDetails[0].split("_");

        // find from spec
        if (spec.matches("^[0-9a-zA-Z]+(_[0-9]+)?(:[0-9a-zA-Z]+)?$")) {
            if (specDetails.length == 2)
                keyGen = KeyPairGenerator.getInstance(algoDetails[0], specDetails[1]);
            else
                keyGen = KeyPairGenerator.getInstance(algoDetails[0]);

            if (algoDetails.length == 2)
                keySize = Integer.parseInt(algoDetails[1]);
        }
        else
            throw new IllegalArgumentException("Spec argument '" + spec + "' should be in format: <Algo>[_<KeySize>][:<Provider>]");

        // initilize Key Generator
        if (keySize >= 0)
            keyGen.initialize(keySize);
        else if (parameters != null) {
            String[] params = parameters.split(":");

            if (algoDetails[0].equalsIgnoreCase("DH"))
                keyGen.initialize(new DHParameterSpec(new BigInteger(params[0], 16), new BigInteger(params[1], 16)));
            else if (algoDetails[0].equalsIgnoreCase("RSA"))
                keyGen.initialize(new RSAKeyGenParameterSpec(Integer.parseInt(params[0]), new BigInteger(params[1], 16)));
            else if (algoDetails[0].equalsIgnoreCase("DSA"))
                throw new ExceptionInInitializerError("No parameter initializer for DSA found.");
        }
        else
            throw new InvalidAlgorithmParameterException("No valid key exchange parameters found.");

        return keyGen.generateKeyPair();
    }

    public static X509Certificate loadAndVerifyCertificate(InputStream inputStream) throws CertificateException {
        X509Certificate cert;

        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

        cert = (X509Certificate) certFactory.generateCertificate(inputStream);

        verifyCertificate(cert);

        return cert;
    }

    public static void verifyCertificate(X509Certificate certificate) throws CertificateException {

        if (certificate == null)
            throw new CertificateException("NULL");

        try {
            CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

            // validate
            URL CRLUrl = null;
            byte[] bytes = certificate.getExtensionValue(CRL_DISTRIBUTION_POINT_OID);
            if (bytes != null)
                CRLUrl = extractURL(bytes);
            if (CRLUrl != null && certFactory.generateCRL(CRLUrl.openStream()).isRevoked(certificate))
                throw new CertificateException("Revoked by CRL obtained from: " + CRLUrl);
        } catch (IOException | CRLException e) {
            throw new RuntimeException(e);
        }
    }

    public static URL extractURL(byte[] bytes) {
        String s = new String(bytes);
        int urlOffset = s.lastIndexOf("http");
        try {
            return (urlOffset >= 0) ? new URL(s.substring(urlOffset)) : null;
        } catch (MalformedURLException e) {
            throw new RuntimeException(e);
        }
    }

    public static short parseCipherSuites(String ciphers) {
        short cipherSuites = 0;

        if (ciphers != null)
            for (String cs : ciphers.split(","))
            {
                int val = Integer.parseInt(cs);
                if (val < 6 && val > 0)
                    cipherSuites += 1<<(val - 1); // set bit (if val = 1, sets 1st bit)
            }

        return cipherSuites;
    }

    public static X509Certificate certificateParser(byte[] bu) {
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            InputStream in = new ByteArrayInputStream(bu);
            X509Certificate cert = (X509Certificate) cf.generateCertificate(in);
            in.close();
            return cert;
        } catch (CertificateException e) {
            return null;
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static PublicKey publicKeyParser(byte[] bytes, String spec) {

        try {
            String algo = Optional.ofNullable(spec)
                    .map(s -> s.split(":"))
                    .map(strings -> strings[0])
                    .map(s -> s.split("_"))
                    .map(strings -> strings[0])
                    .orElseThrow(() -> new IllegalArgumentException("Invalid spec."));

            return KeyFactory.getInstance(algo).generatePublic(new X509EncodedKeySpec(bytes, algo));

        } catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
            throw new RuntimeException(e);
        }

    }

    /**
     *
     * @param trustAnchor represents a CA
     * @param chain the certificate chain to validate
     * @throws SignatureException if the certificate chain contains an
     */
    public static void validateChain(TrustAnchor trustAnchor, X509Certificate[] chain) throws SignatureException
    {
        PublicKey CAkey = Optional.of(trustAnchor).map(TrustAnchor::getTrustedCert)
                .map(X509Certificate::getPublicKey) // get Key from certificate
                .orElseGet(trustAnchor::getCAPublicKey); // or directly

        try {
            chain[chain.length - 1].verify(CAkey); // check if top-level certificate is certified by our CA
            for (int i = chain.length - 1; i > 0; i--) { // check lower-level certificates signatures
                chain[i-1].verify(chain[i].getPublicKey());
            }
        } catch (CertificateException | InvalidKeyException | NoSuchProviderException e) {
            throw new RuntimeException(e);
        } catch (NoSuchAlgorithmException e) {
            throw new SignatureException(e);
        }
    }

}
