package com.aliyun.ati.sdk.agent.verification;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import com.aliyun.ati.sdk.exception.AtiException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Loads the ATI private CA (Identity CA) certificate chain and provides
 * a standard {@link X509TrustManager} rooted in the IDCA trust anchor.
 *
 * <p>The verifier loads a PEM file containing one or more certificates.
 * The last certificate in the file is treated as the root CA (trust
 * anchor); all preceding certificates are treated as intermediates.</p>
 *
 * <p>Use {@link #createTrustManager()} to obtain an {@link X509TrustManager}
 * that can be passed to an {@link javax.net.ssl.SSLContext} so that PKIX
 * validation happens automatically during the TLS handshake.</p>
 */
public final class IdcaChainVerifier {

    private static final Logger LOG =
        LoggerFactory.getLogger(IdcaChainVerifier.class);

    private final List<X509Certificate> intermediates;
    private final TrustAnchor trustAnchor;

    /**
     * Creates a new verifier from a PEM file path.
     *
     * <p>The path may be prefixed with {@code classpath:} to load from
     * the classpath, or an absolute/relative filesystem path.</p>
     *
     * @param trustCertificatePath path to the PEM file containing
     *                             the CA chain
     * @throws AtiException if the file cannot be loaded or contains
     *                      no certificates
     */
    public IdcaChainVerifier(String trustCertificatePath) {
        Objects.requireNonNull(trustCertificatePath,
            "trustCertificatePath must not be null");
        List<X509Certificate> certs =
            loadCertificates(trustCertificatePath);
        if (certs.isEmpty()) {
            throw new AtiException(
                "No certificates found in: " + trustCertificatePath);
        }
        // Last cert in the PEM file is the root CA (trust anchor)
        X509Certificate rootCert = certs.get(certs.size() - 1);
        this.trustAnchor = new TrustAnchor(rootCert, null);
        // Everything except the root is an intermediate
        this.intermediates = certs.size() > 1
            ? Collections.unmodifiableList(
                certs.subList(0, certs.size() - 1))
            : Collections.emptyList();
    }

    /**
     * Package-private constructor for testing with pre-loaded certs.
     *
     * @param chainCerts list of certificates; the last element is the
     *                   root CA
     */
    IdcaChainVerifier(List<X509Certificate> chainCerts) {
        Objects.requireNonNull(chainCerts,
            "chainCerts must not be null");
        if (chainCerts.isEmpty()) {
            throw new IllegalArgumentException(
                "chainCerts must not be empty");
        }
        X509Certificate rootCert =
            chainCerts.get(chainCerts.size() - 1);
        this.trustAnchor = new TrustAnchor(rootCert, null);
        this.intermediates = chainCerts.size() > 1
            ? Collections.unmodifiableList(
                new ArrayList<>(
                    chainCerts.subList(0, chainCerts.size() - 1)))
            : Collections.emptyList();
    }

    /**
     * Creates an {@link X509TrustManager} rooted in the IDCA trust anchor.
     *
     * <p>The returned trust manager contains the root CA certificate and
     * all intermediate certificates so that PKIX chain validation is
     * performed automatically during the TLS handshake.</p>
     *
     * @return a trust manager that trusts the IDCA certificate chain
     * @throws AtiException if the trust manager cannot be created
     */
    public X509TrustManager createTrustManager() {
        try {
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            ks.load(null, null);
            ks.setCertificateEntry("idca-root",
                trustAnchor.getTrustedCert());
            for (int i = 0; i < intermediates.size(); i++) {
                ks.setCertificateEntry("idca-intermediate-" + i,
                    intermediates.get(i));
            }
            TrustManagerFactory tmf = TrustManagerFactory.getInstance(
                TrustManagerFactory.getDefaultAlgorithm());
            tmf.init(ks);
            for (TrustManager tm : tmf.getTrustManagers()) {
                if (tm instanceof X509TrustManager) {
                    return (X509TrustManager) tm;
                }
            }
            throw new AtiException(
                "No X509TrustManager found from TrustManagerFactory");
        } catch (AtiException e) {
            throw e;
        } catch (Exception e) {
            throw new AtiException(
                "Failed to create IDCA TrustManager", e);
        }
    }

    @SuppressWarnings("unchecked")
    private static List<X509Certificate> loadCertificates(String path) {
        try {
            CertificateFactory cf =
                CertificateFactory.getInstance("X.509");
            try (InputStream is = openResource(path)) {
                Collection<X509Certificate> certs =
                    (Collection<X509Certificate>)
                        (Collection<?>) cf.generateCertificates(is);
                return new ArrayList<>(certs);
            }
        } catch (AtiException e) {
            throw e;
        } catch (Exception e) {
            throw new AtiException(
                "Failed to load IDCA certificates from: " + path, e);
        }
    }

    private static InputStream openResource(String path)
            throws Exception {
        if (path.startsWith("classpath:")) {
            String resource = path.substring("classpath:".length());
            InputStream is = IdcaChainVerifier.class
                .getClassLoader().getResourceAsStream(resource);
            if (is == null) {
                throw new AtiException(
                    "IDCA certificate not found on classpath: "
                        + resource);
            }
            return is;
        }
        return Files.newInputStream(Path.of(path));
    }
}
