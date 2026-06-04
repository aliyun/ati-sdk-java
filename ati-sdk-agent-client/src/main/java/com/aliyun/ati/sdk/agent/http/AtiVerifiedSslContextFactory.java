package com.aliyun.ati.sdk.agent.http;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.Objects;

import javax.net.ssl.KeyManager;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

import com.aliyun.ati.sdk.exception.AtiException;

/**
 * Factory for creating {@link SSLContext} with IDCA-rooted trust and
 * ATI certificate capture.
 *
 * <p>The SSLContext created by this factory:</p>
 * <ol>
 *   <li>Validates the server certificate against the ATI private CA
 *       (IDCA) chain via the provided {@link X509TrustManager}</li>
 *   <li>Captures the server certificate for post-handshake DANE/Badge
 *       verification via {@link CertificateCapturingTrustManager}</li>
 *   <li>Optionally includes a client certificate for mTLS</li>
 * </ol>
 *
 * <h2>Usage</h2>
 * <pre>{@code
 * X509TrustManager idcaTm = idcaChainVerifier.createTrustManager();
 * AtiVerifiedSslContextFactory.Result result =
 *     AtiVerifiedSslContextFactory.create(idcaTm, null, null);
 * SSLContext sslContext = result.getSslContext();
 * CertificateCapturingTrustManager tm = result.getTrustManager();
 *
 * HttpClient httpClient = HttpClient.newBuilder()
 *     .sslContext(sslContext)
 *     .build();
 *
 * // After TLS handshake, retrieve captured certificate
 * X509Certificate serverCert = tm.getLastCapturedServerCert();
 * }</pre>
 *
 * @see CertificateCapturingTrustManager
 */
public final class AtiVerifiedSslContextFactory {

    private AtiVerifiedSslContextFactory() {
        // No instantiation
    }

    /**
     * Creates an SSLContext with IDCA-rooted trust, certificate capture,
     * and optional mTLS.
     *
     * @param idcaTrustManager the IDCA trust manager for validating server
     *                         certificates against the ATI private CA chain
     * @param keystorePath     path to a PKCS12 keystore for client
     *                         certificate (prefix with {@code classpath:}
     *                         for classpath resources), or {@code null}
     *                         for server-only authentication
     * @param keystorePassword the keystore password, or {@code null}
     * @return a {@link Result} containing the SSLContext and capturing
     *         trust manager
     * @throws NullPointerException if idcaTrustManager is null
     * @throws AtiException if SSL context creation fails
     */
    public static Result create(X509TrustManager idcaTrustManager,
                                String keystorePath, String keystorePassword) {
        Objects.requireNonNull(idcaTrustManager, "idcaTrustManager must not be null");
        try {
            // Wrap IDCA trust manager with capturing trust manager
            CertificateCapturingTrustManager capturingTm =
                new CertificateCapturingTrustManager(idcaTrustManager);

            // Load client keystore for mTLS if provided
            KeyManager[] keyManagers = null;
            if (keystorePath != null) {
                keyManagers = loadKeyManagers(keystorePath, keystorePassword);
            }

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(keyManagers, new TrustManager[]{capturingTm}, null);

            return new Result(sslContext, capturingTm);
        } catch (AtiException e) {
            throw e;
        } catch (Exception e) {
            throw new AtiException("Failed to create SSL context", e);
        }
    }

    private static KeyManager[] loadKeyManagers(String keystorePath,
            String password) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        char[] pwChars = password != null ? password.toCharArray() : null;

        if (keystorePath.startsWith("classpath:")) {
            String resource = keystorePath.substring("classpath:".length());
            try (InputStream is = AtiVerifiedSslContextFactory.class
                    .getClassLoader().getResourceAsStream(resource)) {
                if (is == null) {
                    throw new AtiException(
                        "Keystore not found on classpath: " + resource);
                }
                ks.load(is, pwChars);
            }
        } else {
            try (InputStream is = Files.newInputStream(Path.of(keystorePath))) {
                ks.load(is, pwChars);
            }
        }

        KeyManagerFactory kmf = KeyManagerFactory.getInstance(
            KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, pwChars);
        return kmf.getKeyManagers();
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
