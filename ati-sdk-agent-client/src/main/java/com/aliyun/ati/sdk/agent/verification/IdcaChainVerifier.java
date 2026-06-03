package com.aliyun.ati.sdk.agent.verification;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertPathValidatorException;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Set;

import com.aliyun.ati.sdk.exception.AtiException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Verifies that a peer certificate was issued by the ATI private CA
 * (Identity CA) using Java's PKIX {@link CertPathValidator}.
 *
 * <p>The verifier loads a PEM file containing one or more certificates.
 * The last certificate in the file is treated as the root CA (trust
 * anchor); all preceding certificates are treated as intermediates.</p>
 *
 * <p>Revocation checking is disabled because the ATI Identity CA is a
 * private CA that does not publish CRL/OCSP endpoints.</p>
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
     * Verifies the peer certificate against the IDCA trust anchor.
     *
     * @param peerCert the certificate to verify
     * @return the verification result
     */
    public VerificationResult verify(X509Certificate peerCert) {
        Objects.requireNonNull(peerCert, "peerCert must not be null");
        try {
            CertificateFactory cf =
                CertificateFactory.getInstance("X.509");
            List<X509Certificate> pathCerts = new ArrayList<>();
            pathCerts.add(peerCert);
            pathCerts.addAll(intermediates);
            CertPath certPath = cf.generateCertPath(pathCerts);

            CertPathValidator validator =
                CertPathValidator.getInstance("PKIX");
            PKIXParameters params =
                new PKIXParameters(Set.of(trustAnchor));
            params.setRevocationEnabled(false);
            validator.validate(certPath, params);

            LOG.debug("IDCA chain verification succeeded");
            return VerificationResult.success(
                VerificationResult.Type.IDCA);
        } catch (CertPathValidatorException e) {
            LOG.debug("IDCA chain verification failed: {}",
                e.getMessage());
            return VerificationResult.failure(
                VerificationResult.Type.IDCA,
                VerificationResult.Status.MISMATCH,
                e.getMessage());
        } catch (Exception e) {
            LOG.warn("IDCA chain verification error: {}",
                e.getMessage());
            return VerificationResult.failure(
                VerificationResult.Type.IDCA,
                VerificationResult.Status.ERROR,
                e.getMessage());
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
