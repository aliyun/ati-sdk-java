package com.aliyun.ati.sdk.agent.verification;

import com.aliyun.ati.sdk.crypto.CertificateUtils;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.GeneralSecurityException;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;

/**
 * Production IDCA Chain shipped by the SDK: exactly one {@code IDCA Root} and one
 * {@code IDCA Intermediate}.
 *
 * <p>Used as the Server Agent's default trust material for Client Verification.
 * An operator-supplied PEM path replaces this pair entirely — it is never merged
 * with the shipped chain.</p>
 *
 * @see com.aliyun.ati.sdk.agent.VerificationPolicy#requiresIdcaTrust()
 */
public final class IdcaChain {

    static final String SHIPPED_RESOURCE = "/com/aliyun/ati/sdk/agent/idca/idca-chain.crt";

    /**
     * Spring {@code Ssl.setTrustCertificate} location for the shipped production chain.
     */
    public static final String SHIPPED_CLASSPATH_LOCATION =
        "classpath:com/aliyun/ati/sdk/agent/idca/idca-chain.crt";

    private final X509Certificate root;
    private final X509Certificate intermediate;

    private IdcaChain(X509Certificate root, X509Certificate intermediate) {
        this.root = Objects.requireNonNull(root, "root");
        this.intermediate = Objects.requireNonNull(intermediate, "intermediate");
    }

    /**
     * Loads the production IDCA Chain bundled in the SDK.
     *
     * @return the shipped two-certificate chain
     * @throws IllegalStateException if the bundled resource is missing or invalid
     */
    public static IdcaChain shipped() {
        try (InputStream in = IdcaChain.class.getResourceAsStream(SHIPPED_RESOURCE)) {
            if (in == null) {
                throw new IllegalStateException("Shipped IDCA Chain resource not found: " + SHIPPED_RESOURCE);
            }
            String pem = new String(in.readAllBytes(), StandardCharsets.US_ASCII);
            return parse(pem, "shipped IDCA Chain");
        } catch (IOException e) {
            throw new IllegalStateException("Failed to read shipped IDCA Chain", e);
        }
    }

    /**
     * Loads an IDCA Chain from a PEM file that must contain exactly two certificates.
     *
     * @param pemPath filesystem path to a two-certificate PEM
     * @return the parsed chain
     * @throws IllegalStateException if the file is missing or not exactly two certificates
     */
    public static IdcaChain fromPemFile(Path pemPath) {
        Objects.requireNonNull(pemPath, "pemPath");
        String pem;
        try {
            pem = Files.readString(pemPath, StandardCharsets.US_ASCII);
        } catch (IOException e) {
            throw new IllegalStateException("Failed to read IDCA Chain override: " + pemPath, e);
        }
        return parse(pem, pemPath.toString());
    }

    /**
     * Resolves the Spring trust-certificate location for a Server Agent.
     *
     * <p>Blank override → shipped production chain. Non-blank → the given path,
     * after validating it is a two-certificate PEM (replace, not merge).</p>
     *
     * @param overridePemPath optional filesystem path; {@code null} or blank uses the shipped chain
     * @return a {@code classpath:} location or an absolute/relative file path
     */
    public static String trustCertificateLocation(String overridePemPath) {
        if (overridePemPath == null || overridePemPath.isBlank()) {
            shipped();
            return SHIPPED_CLASSPATH_LOCATION;
        }
        fromPemFile(Path.of(overridePemPath));
        return overridePemPath;
    }

    static IdcaChain parse(String pem, String source) {
        List<X509Certificate> certs;
        try {
            certs = CertificateUtils.parseCertificateChain(pem);
        } catch (RuntimeException e) {
            throw new IllegalStateException("Invalid IDCA Chain PEM (" + source + ")", e);
        }
        if (certs.size() != 2) {
            throw new IllegalStateException(
                "IDCA Chain must contain exactly 2 certificates (root + intermediate), found "
                    + certs.size() + " in " + source);
        }
        return identify(certs.get(0), certs.get(1), source);
    }

    private static IdcaChain identify(X509Certificate first, X509Certificate second, String source) {
        try {
            if (isSelfSigned(first) && issuedBy(second, first)) {
                return new IdcaChain(first, second);
            }
            if (isSelfSigned(second) && issuedBy(first, second)) {
                return new IdcaChain(second, first);
            }
        } catch (IllegalStateException e) {
            throw new IllegalStateException(
                e.getMessage() + " (" + source + ")", e.getCause() == null ? e : e.getCause());
        }
        throw new IllegalStateException(
            "IDCA Chain must be one self-signed Root and one Intermediate issued by that Root ("
                + source + ")");
    }

    static boolean isSelfSigned(X509Certificate cert) {
        if (!cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal())) {
            return false;
        }
        return signatureMatches(cert, cert);
    }

    static boolean issuedBy(X509Certificate subject, X509Certificate issuer) {
        return signatureMatches(subject, issuer);
    }

    /**
     * {@code true} if {@code subject} verifies against {@code issuer}'s public key.
     *
     * <p>{@link java.security.SignatureException} means the signatures do not match (chain
     * structure). Other verification failures (missing algorithm, FIPS, invalid key) are
     * configuration errors and are rethrown with the original cause — same pattern as
     * {@link com.aliyun.ati.sdk.agent.verification.crl.CrlValidator#verifySignature}.</p>
     */
    static boolean signatureMatches(X509Certificate subject, X509Certificate issuer) {
        try {
            subject.verify(issuer.getPublicKey());
            return true;
        } catch (SignatureException e) {
            return false;
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new IllegalStateException(
                "IDCA certificate signature verification failed; check JCE/FIPS provider support", e);
        }
    }

    public X509Certificate root() {
        return root;
    }

    public X509Certificate intermediate() {
        return intermediate;
    }
}
