package com.aliyun.ati.sdk.agent.http;

import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ConcurrentMap;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * A TrustManager that captures server certificates during TLS handshake.
 *
 * <p>This TrustManager performs standard PKI validation (delegating to the
 * underlying trust manager), while capturing the server certificate chain for
 * post-handshake DANE/Badge verification.</p>
 *
 * <p>Certificates are stored in a {@link ConcurrentHashMap} keyed by the
 * leaf certificate's subject DN. This class extends
 * {@link X509ExtendedTrustManager} (not just {@link X509TrustManager})
 * because {@code java.net.http.HttpClient} requires an extended trust
 * manager.</p>
 *
 * <h2>Usage</h2>
 * <pre>{@code
 * X509TrustManager systemTm = getSystemTrustManager();
 * CertificateCapturingTrustManager capturingTm =
 *     new CertificateCapturingTrustManager(systemTm);
 *
 * SSLContext sslContext = SSLContext.getInstance("TLS");
 * sslContext.init(null, new TrustManager[]{capturingTm}, null);
 *
 * // After TLS handshake, retrieve captured certificate
 * X509Certificate serverCert = capturingTm.getLastCapturedServerCert();
 * }</pre>
 */
public final class CertificateCapturingTrustManager extends X509ExtendedTrustManager {

    private final X509TrustManager delegate;
    private final ConcurrentMap<String, X509Certificate[]> capturedCerts =
        new ConcurrentHashMap<>();

    /**
     * Creates a certificate-capturing trust manager.
     *
     * @param delegate the underlying trust manager for PKI validation
     */
    public CertificateCapturingTrustManager(X509TrustManager delegate) {
        this.delegate = Objects.requireNonNull(delegate, "delegate must not be null");
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        delegate.checkServerTrusted(chain, authType);
        captureCertificates(chain);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType,
            Socket socket) throws CertificateException {
        if (delegate instanceof X509ExtendedTrustManager) {
            ((X509ExtendedTrustManager) delegate)
                .checkServerTrusted(chain, authType, socket);
        } else {
            delegate.checkServerTrusted(chain, authType);
        }
        String hostname = extractHostname(socket);
        if (hostname != null) {
            captureCertificates(hostname, chain);
        } else {
            captureCertificates(chain);
        }
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType,
            SSLEngine engine) throws CertificateException {
        if (delegate instanceof X509ExtendedTrustManager) {
            ((X509ExtendedTrustManager) delegate)
                .checkServerTrusted(chain, authType, engine);
        } else {
            delegate.checkServerTrusted(chain, authType);
        }
        String hostname = (engine != null) ? engine.getPeerHost() : null;
        if (hostname != null) {
            captureCertificates(hostname, chain);
        } else {
            captureCertificates(chain);
        }
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType)
            throws CertificateException {
        delegate.checkClientTrusted(chain, authType);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType,
            Socket socket) throws CertificateException {
        if (delegate instanceof X509ExtendedTrustManager) {
            ((X509ExtendedTrustManager) delegate)
                .checkClientTrusted(chain, authType, socket);
        } else {
            delegate.checkClientTrusted(chain, authType);
        }
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType,
            SSLEngine engine) throws CertificateException {
        if (delegate instanceof X509ExtendedTrustManager) {
            ((X509ExtendedTrustManager) delegate)
                .checkClientTrusted(chain, authType, engine);
        } else {
            delegate.checkClientTrusted(chain, authType);
        }
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return delegate.getAcceptedIssuers();
    }

    /**
     * Returns the captured server certificate chain for the given key.
     *
     * <p>The key is typically the leaf certificate's subject DN
     * ({@code X500Principal.getName()}) or the hostname used during
     * the handshake.</p>
     *
     * @param key the subject DN or hostname key
     * @return a defensive copy of the certificate chain, or {@code null}
     *         if no chain was captured for the key
     */
    public X509Certificate[] getCapturedCerts(String key) {
        X509Certificate[] certs = capturedCerts.get(key);
        return certs != null ? certs.clone() : null;
    }

    /**
     * Returns the last captured server certificate (leaf certificate).
     *
     * <p>Convenience method for simple single-connection use cases.
     * Returns the first element of any captured chain.</p>
     *
     * @return the leaf certificate from the most recently captured chain,
     *         or {@code null} if nothing has been captured
     */
    public X509Certificate getLastCapturedServerCert() {
        return capturedCerts.values().stream()
            .filter(chain -> chain.length > 0)
            .map(chain -> chain[0])
            .findFirst()
            .orElse(null);
    }

    /**
     * Captures the certificate chain using the leaf certificate's subject DN as
     * the key.
     */
    private void captureCertificates(X509Certificate[] chain) {
        if (chain != null && chain.length > 0) {
            String key = chain[0].getSubjectX500Principal().getName();
            capturedCerts.put(key, chain.clone());
        }
    }

    /**
     * Captures the certificate chain using the specified hostname as the key.
     */
    private void captureCertificates(String hostname, X509Certificate[] chain) {
        if (chain != null && chain.length > 0) {
            capturedCerts.put(hostname, chain.clone());
        }
    }

    /**
     * Extracts the hostname from a socket's remote address.
     */
    private static String extractHostname(Socket socket) {
        if (socket != null
                && socket.getRemoteSocketAddress() instanceof InetSocketAddress addr) {
            return addr.getHostString();
        }
        return null;
    }
}
