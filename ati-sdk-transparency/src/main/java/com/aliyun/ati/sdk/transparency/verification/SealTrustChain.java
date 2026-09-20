package com.aliyun.ati.sdk.transparency.verification;

import com.aliyun.ati.sdk.crypto.CertificateUtils;

import java.security.GeneralSecurityException;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;

/**
 * The Seal CA Chain the SDK trusts when path-validating a {@code seal.certificate}:
 * exactly one {@code Seal CA Root} and one {@code Seal CA Intermediate}.
 *
 * <p>Mirrors {@code com.aliyun.ati.sdk.agent.verification.IdcaChain}: the pair is validated on
 * construction (one self-signed Root, one Intermediate issued by that Root) and fails closed
 * otherwise. This is the expand-phase injection point — a caller supplies the chain so the
 * certificate-based {@link SealVerifier} overload can anchor on it. The shipped classpath
 * resource and the operator override are wired in a later increment (see ADR 0011).</p>
 */
public final class SealTrustChain {

    private final X509Certificate root;
    private final X509Certificate intermediate;

    private SealTrustChain(X509Certificate root, X509Certificate intermediate) {
        this.root = Objects.requireNonNull(root, "root");
        this.intermediate = Objects.requireNonNull(intermediate, "intermediate");
    }

    /**
     * Builds a chain from an explicit Root + Intermediate pair, validating that the root is
     * self-signed and the intermediate is issued by that root. Order is not significant.
     *
     * @param root the Seal CA Root (trust anchor)
     * @param intermediate the Seal CA Intermediate issued by {@code root}
     * @return the validated two-certificate chain
     * @throws IllegalStateException if the pair is not a Root + its Intermediate
     */
    public static SealTrustChain of(X509Certificate root, X509Certificate intermediate) {
        return identify(root, intermediate, "injected Seal CA Chain");
    }

    /**
     * Builds a chain from a PEM string that must contain exactly two certificates.
     *
     * @param pem a two-certificate PEM (Root + Intermediate, either order)
     * @return the parsed chain
     * @throws IllegalStateException if the PEM is invalid or is not a Root + Intermediate pair
     */
    public static SealTrustChain fromPem(String pem) {
        return parse(pem, "Seal CA Chain PEM");
    }

    static SealTrustChain parse(String pem, String source) {
        List<X509Certificate> certs;
        try {
            certs = CertificateUtils.parseCertificateChain(pem);
        } catch (RuntimeException e) {
            throw new IllegalStateException("Invalid Seal CA Chain PEM (" + source + ")", e);
        }
        if (certs.size() != 2) {
            throw new IllegalStateException(
                "Seal CA Chain must contain exactly 2 certificates (root + intermediate), found "
                    + certs.size() + " in " + source);
        }
        return identify(certs.get(0), certs.get(1), source);
    }

    private static SealTrustChain identify(X509Certificate first, X509Certificate second, String source) {
        try {
            if (isSelfSigned(first) && issuedBy(second, first)) {
                return new SealTrustChain(first, second);
            }
            if (isSelfSigned(second) && issuedBy(first, second)) {
                return new SealTrustChain(second, first);
            }
        } catch (IllegalStateException e) {
            throw new IllegalStateException(
                e.getMessage() + " (" + source + ")", e.getCause() == null ? e : e.getCause());
        }
        throw new IllegalStateException(
            "Seal CA Chain must be one self-signed Root and one Intermediate issued by that Root ("
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
     * {@code IdcaChain#signatureMatches}.</p>
     */
    static boolean signatureMatches(X509Certificate subject, X509Certificate issuer) {
        try {
            subject.verify(issuer.getPublicKey());
            return true;
        } catch (SignatureException e) {
            return false;
        } catch (GeneralSecurityException | IllegalArgumentException e) {
            throw new IllegalStateException(
                "Seal CA certificate signature verification failed; check JCE/FIPS provider support", e);
        }
    }

    public X509Certificate root() {
        return root;
    }

    public X509Certificate intermediate() {
        return intermediate;
    }
}
