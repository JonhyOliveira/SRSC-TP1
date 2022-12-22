package utils;

import javax.crypto.KeyAgreement;
import javax.crypto.Mac;
import javax.crypto.spec.DHParameterSpec;
import java.io.*;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Optional;

public class HandshakeUtils {

    public static final String CRL_DISTRIBUTION_POINT_OID = "2.5.29.31";

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
                if (!cs.isEmpty()) {
                    int val = Integer.parseInt(cs);
                    if (val < 6 && val > 0)
                        cipherSuites += 1 << (val - 1); // set bit (if val = 1, sets 1st bit)
                }
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

    public static byte[] composeHandshake(short cipherSuites, PublicKey agreementKey, Certificate[] certificateChain,
                                          Signature signingAlgo, Mac integrityCheckAlgo) throws HandshakeException {
        return composeHandshake(cipherSuites, agreementKey, certificateChain, signingAlgo, integrityCheckAlgo, new byte[0]);
    }

    public static byte[] composeHandshake(short cipherSuites, PublicKey agreementKey, Certificate[] certificateChain,
                                          Signature signingAlgo, Mac integrityCheckAlgo, byte[] extraData) throws HandshakeException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream outputStream = new DataOutputStream(baos);

        try {
            // start with ciphersuites
            outputStream.writeShort(cipherSuites);
            // key exchange
            sendBytes(outputStream, agreementKey.getEncoded());
            // certificate chain
            outputStream.writeShort(certificateChain.length);
            for (Certificate certificate : certificateChain)
                sendBytes(outputStream, certificate.getEncoded());

            // attach extra data
            outputStream.writeShort(extraData.length);
            if (extraData.length > 0)
                outputStream.write(extraData);

            // sign it
            outputStream.flush();
            signingAlgo.update(baos.toByteArray());
            byte[] signature = signingAlgo.sign();

            outputStream.write(signature);
            outputStream.writeShort(signature.length);

            // attach integrity check
            outputStream.flush();
            integrityCheckAlgo.update(baos.toByteArray());
            outputStream.write(integrityCheckAlgo.doFinal());

            outputStream.flush();
            return baos.toByteArray();

        } catch (IOException | SignatureException | CertificateEncodingException e) {
            throw new HandshakeException("Error composing handshake", e);
        }
    }

    /**
     * @return extra data sent inside the handshake
     * @throws HandshakeException
     */
    public static byte[] validateHandshake(byte[] message, Mac integrityCheck, TrustAnchor anchor) throws HandshakeException {
        byte[] check = Arrays.copyOfRange(message, message.length - integrityCheck.getMacLength(), message.length),
                remainder = Arrays.copyOfRange(message, 0, message.length - integrityCheck.getMacLength());

        // check integrity
        if (!Arrays.equals(check, integrityCheck.doFinal(remainder)))
            throw new HandshakeException("Integrity check failed");

        ByteBuffer buf = ByteBuffer.wrap(remainder);
        int signLen = buf.getShort(remainder.length - Short.BYTES); // signature length
        byte[] sign = Arrays.copyOfRange(remainder, remainder.length - Short.BYTES - signLen,
                remainder.length - Short.BYTES);

        buf.getShort();
        buf.position(Short.BYTES * 2 + buf.getShort()); // skip ciphersuites and key agreement

        // verify certificates
        int len = buf.getShort(); // cert chain size
        X509Certificate[] certChain = new X509Certificate[len];

        try {
            for (int i = 0; i < len; i++) {
                int certLen = buf.getShort();
                byte[] bytes = new byte[certLen];
                buf.get(bytes, 0, certLen);
                certChain[i] = certificateParser(bytes);
                verifyCertificate(certChain[i]);
            }
        } catch (CertificateException e) {
            throw new HandshakeException(e);
        }

        // extract extra data
        byte[] extraData = new byte[buf.getShort()];
        if (extraData.length > 0)
            buf.get(extraData, 0, extraData.length);

        // verify signature
        try {
            Signature signAlgo = Signature.getInstance("SHA256with" + certChain[0].getPublicKey().getAlgorithm());

            signAlgo.initVerify(certChain[0].getPublicKey());
            signAlgo.update(Arrays.copyOfRange(remainder, 0, remainder.length - signLen - Short.BYTES));
            if (!signAlgo.verify(sign))
                throw new HandshakeException("Signature check failed");
        } catch (SignatureException | InvalidKeyException e) {
            throw new HandshakeException("Error signing message", e);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        /* validate chain */
        if (anchor != null) {
            try {
                validateChain(anchor, certChain);
            } catch (SignatureException e) {
                throw new HandshakeException("Chain is not trustable", e);
            }
        } /* */

        return extraData;
    }

    public static void sendBytes(OutputStream outputStream, byte[] bytes) throws IOException {
        new DataOutputStream(outputStream).writeShort(bytes.length);
        outputStream.write(bytes);
    }

    public static byte[] receiveBytes(InputStream inputStream) throws IOException {
        return inputStream.readNBytes(new DataInputStream(inputStream).readShort());
    }

}
