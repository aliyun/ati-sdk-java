package com.aliyun.ati.sdk.agent.http;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import com.aliyun.ati.sdk.exception.AtiException;

/**
 * Factory for creating {@link SSLContext} with standard PKI trust and
 * ATI certificate capture.
 *
 * <p>The SSLContext created by this factory:</p>
 * <ol>
 *   <li>Validates the server certificate against the system CA trust
 *       store (public CA — standard HTTPS)</li>
 *   <li>Captures the server certificate for post-handshake DANE/Badge
 *       verification via {@link CertificateCapturingTrustManager}</li>
 *   <li>Optionally includes an IDCA identity certificate for mTLS</li>
 * </ol>
 */
public final class AtiVerifiedSslContextFactory {

    private AtiVerifiedSslContextFactory() {
        // No instantiation
    }

    /**
     * Creates an SSLContext with system CA trust, certificate capture,
     * and optional mTLS identity certificate.
     *
     * @param certificatePath    path to a PEM-encoded IDCA identity
     *                           certificate for mTLS, or {@code null}
     * @param privateKeyPath     path to a PEM-encoded PKCS8 private key
     *                           matching the certificate, or {@code null}
     * @return a {@link Result} containing the SSLContext and capturing
     *         trust manager
     */
    public static Result create(String certificatePath,
                                String privateKeyPath) {

        if (certificatePath != null && privateKeyPath == null) {
            throw new AtiException(
                "privateKeyPath is required when certificatePath is set");
        }
        if (privateKeyPath != null && certificatePath == null) {
            throw new AtiException(
                "certificatePath is required when privateKeyPath is set");
        }

        try {
            X509TrustManager systemTm = getSystemTrustManager();
            CertificateCapturingTrustManager capturingTm =
                new CertificateCapturingTrustManager(systemTm);

            KeyManager[] keyManagers = null;
            if (certificatePath != null) {
                keyManagers = loadKeyManagers(
                    certificatePath, privateKeyPath);
            }

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(
                keyManagers, new TrustManager[]{capturingTm}, null);

            return new Result(sslContext, capturingTm);
        } catch (AtiException e) {
            throw e;
        } catch (Exception e) {
            throw new AtiException(
                "Failed to create SSL context", e);
        }
    }

    private static X509TrustManager getSystemTrustManager()
            throws Exception {
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(
            TrustManagerFactory.getDefaultAlgorithm());
        tmf.init((KeyStore) null);
        for (TrustManager tm : tmf.getTrustManagers()) {
            if (tm instanceof X509TrustManager) {
                return (X509TrustManager) tm;
            }
        }
        throw new AtiException(
            "No X509TrustManager found in system trust store");
    }

    private static KeyManager[] loadKeyManagers(
            String certificatePath,
            String privateKeyPath) throws Exception {
        X509Certificate cert = loadCertificate(certificatePath);
        PrivateKey key = loadPrivateKey(privateKeyPath);
        validateKeyPair(cert, key);

        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("identity", key, new char[0],
            new java.security.cert.Certificate[]{cert});

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(
            KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, new char[0]);
        return kmf.getKeyManagers();
    }

    @SuppressWarnings("unchecked")
    private static X509Certificate loadCertificate(String path)
            throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        try (InputStream is = openResource(path)) {
            return (X509Certificate) cf.generateCertificate(is);
        }
    }

    private static PrivateKey loadPrivateKey(String path)
            throws Exception {
        String pem;
        try (InputStream is = openResource(path)) {
            pem = new String(is.readAllBytes(), StandardCharsets.UTF_8);
        }
        String base64 = pem
            .replace("-----BEGIN PRIVATE KEY-----", "")
            .replace("-----END PRIVATE KEY-----", "")
            .replaceAll("\\s+", "");
        byte[] decoded = Base64.getDecoder().decode(base64);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decoded);
        // Try EC first, then RSA
        try {
            return KeyFactory.getInstance("EC")
                .generatePrivate(keySpec);
        } catch (Exception e) {
            return KeyFactory.getInstance("RSA")
                .generatePrivate(keySpec);
        }
    }

    private static void validateKeyPair(X509Certificate cert,
            PrivateKey key) throws Exception {
        byte[] testData = "ati-key-pair-validation".getBytes(
            StandardCharsets.UTF_8);
        String algorithm = key.getAlgorithm().equals("EC")
            ? "SHA256withECDSA" : "SHA256withRSA";
        java.security.Signature sig =
            java.security.Signature.getInstance(algorithm);
        sig.initSign(key);
        sig.update(testData);
        byte[] signature = sig.sign();
        sig.initVerify(cert.getPublicKey());
        sig.update(testData);
        if (!sig.verify(signature)) {
            throw new AtiException(
                "Identity certificate and private key do not match");
        }
    }

    private static InputStream openResource(String path)
            throws Exception {
        if (path.startsWith("classpath:")) {
            String resource = path.substring("classpath:".length());
            InputStream is = AtiVerifiedSslContextFactory.class
                .getClassLoader().getResourceAsStream(resource);
            if (is == null) {
                throw new AtiException(
                    "Resource not found on classpath: " + resource);
            }
            return is;
        }
        return Files.newInputStream(Path.of(path));
    }

    /**
     * Bundles the {@link SSLContext} with the
     * {@link CertificateCapturingTrustManager} so callers can access
     * captured certificates after the TLS handshake.
     */
    public static final class Result {

        private final SSLContext sslContext;
        private final CertificateCapturingTrustManager trustManager;

        Result(SSLContext sslContext,
                CertificateCapturingTrustManager trustManager) {
            this.sslContext = sslContext;
            this.trustManager = trustManager;
        }

        /**
         * Returns the configured SSLContext.
         *
         * @return the SSLContext
         */
        public SSLContext getSslContext() {
            return sslContext;
        }

        /**
         * Returns the capturing trust manager used by this SSLContext.
         *
         * @return the trust manager
         */
        public CertificateCapturingTrustManager getTrustManager() {
            return trustManager;
        }
    }
}
