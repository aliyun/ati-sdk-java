package com.aliyun.ati.sdk.transparency.verification;

import com.aliyun.ati.sdk.crypto.CertificateUtils;
import com.aliyun.ati.sdk.transparency.model.MerkleProof;
import com.aliyun.ati.sdk.transparency.model.Seal;
import com.aliyun.ati.sdk.transparency.model.TransparencyLog;
import com.aliyun.ati.sdk.transparency.scitt.MerkleProofVerifier;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.erdtman.jcs.JsonCanonicalizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.CertPath;
import java.security.cert.CertPathValidator;
import java.security.cert.CertificateFactory;
import java.security.cert.PKIXParameters;
import java.security.cert.TrustAnchor;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

/**
 * Verifies the cryptographic seal and Merkle inclusion proof of a CNNIC TL response.
 *
 * <p>Per spec 8.2, badge verification should include:</p>
 * <ul>
 *   <li><b>Seal signature verification:</b> SHA-256withRSA over RFC 8785 JCS-canonicalized
 *       content (status, schemaVersion, payload, evidenceRef). {@code signatureAlgorithm}
 *       must be SHA-256withRSA (normalized); any other value fails.</li>
 *   <li><b>Merkle proof verification:</b> RFC 9162 inclusion proof that the log entry
 *       is committed to the transparency log's Merkle tree</li>
 * </ul>
 *
 * <p>This class extracts and formalizes the verification algorithms that were previously
 * proven in {@code SealVerifierTest}.</p>
 */
public final class SealVerifier {

    private static final Logger LOG = LoggerFactory.getLogger(SealVerifier.class);

    private static final ObjectMapper MAPPER = createMapper();

    /**
     * The CNNIC ATI signing identity the leaf Seal Certificate Subject must carry. The Seal CA is a
     * shared UniTrust CA, so chain validation alone would let any certificate under it impersonate
     * the TL signing cert; the leaf is therefore bound to this Organization + Organizational Unit
     * (ADR 0011). {@code O} is CNNIC's registered organization name.
     */
    private static final String EXPECTED_LEAF_ORGANIZATION = "中国互联网络信息中心";
    private static final String EXPECTED_LEAF_ORGANIZATIONAL_UNIT = "ATI";

    private SealVerifier() {
        // Utility class
    }

    private static ObjectMapper createMapper() {
        ObjectMapper mapper = new ObjectMapper();
        mapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
        return mapper;
    }

    /**
     * Result of seal and/or Merkle proof verification.
     *
     * @param sealValid true if the seal signature verified successfully, null if no seal present
     * @param merkleValid true if the Merkle proof verified successfully, null if no proof present
     * @param failureReason human-readable reason if verification failed, null on success
     */
    public record VerificationResult(
        Boolean sealValid,
        Boolean merkleValid,
        String failureReason
    ) {
        /**
         * Returns true if all present verifications passed.
         * Returns true if no seal/merkle data is present (backwards compat with non-CNNIC TLs).
         */
        public boolean isValid() {
            if (sealValid != null && !sealValid) {
                return false;
            }
            if (merkleValid != null && !merkleValid) {
                return false;
            }
            return true;
        }

        static VerificationResult success(Boolean sealValid, Boolean merkleValid) {
            return new VerificationResult(sealValid, merkleValid, null);
        }

        static VerificationResult failure(String reason) {
            return new VerificationResult(false, null, reason);
        }

        static VerificationResult merkleFailure(Boolean sealValid, String reason) {
            return new VerificationResult(sealValid, false, reason);
        }

        /**
         * Returns a result indicating no cryptographic verification was possible
         * (e.g., for legacy TL responses without seal/merkle data).
         */
        static VerificationResult noVerificationData() {
            return new VerificationResult(null, null, null);
        }
    }

    /**
     * Verifies both the seal signature and Merkle inclusion proof of a TL response against the
     * SDK-shipped Seal CA Chain.
     *
     * <p>Convenience overload equivalent to {@code verify(log, SealTrustChain.shipped())}. The seal
     * signature is verified with the public key inside {@code seal.certificate}, and that Seal
     * Certificate is PKIX path-validated to the shipped Seal CA Chain (ADR 0011). A Seal without
     * {@code seal.certificate} fails closed — the legacy self-asserted {@code seal.publicKey} path
     * is gone.</p>
     *
     * <p>If the response has no seal or merkle data (e.g., legacy TL format),
     * verification is skipped and the result is considered valid for backwards compatibility.</p>
     *
     * @param log the transparency log response to verify
     * @return the verification result
     */
    public static VerificationResult verify(TransparencyLog log) {
        return verify(log, SealTrustChain.shipped());
    }

    /**
     * Verifies both the seal signature and Merkle inclusion proof of a TL response using the
     * certificate-based path: {@code seal.signature} is verified with the public key inside
     * {@code seal.certificate}, and that Seal Certificate is PKIX path-validated to the supplied
     * {@link SealTrustChain} (ADR 0011).
     *
     * <p>Any chain failure (missing certificate, path build, expiry, Subject mismatch,
     * signature mismatch) surfaces as a seal-verification failure.</p>
     *
     * @param log the transparency log response to verify
     * @param trustChain the Seal CA Chain (Root + Intermediate) to anchor path validation on
     * @return the verification result
     */
    public static VerificationResult verify(TransparencyLog log, SealTrustChain trustChain) {
        Objects.requireNonNull(trustChain, "trustChain is required");
        return verifyInternal(log, trustChain);
    }

    private static VerificationResult verifyInternal(TransparencyLog log, SealTrustChain trustChain) {
        if (log == null) {
            return VerificationResult.failure("TransparencyLog is null");
        }

        boolean hasSeal = log.getSeal() != null && log.getSeal().getSignature() != null;
        boolean hasMerkle = log.getMerkleProof() != null && log.getMerkleProof().getLeafHash() != null;

        if (!hasSeal && !hasMerkle) {
            LOG.debug("No seal or Merkle data in TL response, skipping verification");
            return VerificationResult.noVerificationData();
        }

        // Verify seal if present
        Boolean sealValid = null;
        if (hasSeal) {
            try {
                sealValid = verifySealWithCertificate(log, trustChain);
                if (!sealValid) {
                    LOG.warn("Seal signature verification failed");
                    return VerificationResult.failure("Seal signature verification failed");
                }
                LOG.debug("Seal signature verified successfully");
            } catch (Exception e) {
                LOG.warn("Seal verification error: {}", e.getMessage());
                return VerificationResult.failure("Seal verification error: " + e.getMessage());
            }
        }

        // Verify Merkle proof if present
        Boolean merkleValid = null;
        if (hasMerkle) {
            try {
                merkleValid = verifyMerkleProof(log.getMerkleProof());
                if (!merkleValid) {
                    LOG.warn("Merkle proof verification failed");
                    return VerificationResult.merkleFailure(sealValid, "Merkle proof verification failed");
                }
                LOG.debug("Merkle proof verified successfully");
            } catch (Exception e) {
                LOG.warn("Merkle proof verification error: {}", e.getMessage());
                return VerificationResult.merkleFailure(sealValid, "Merkle proof error: " + e.getMessage());
            }
        }

        return VerificationResult.success(sealValid, merkleValid);
    }

    /**
     * Verifies the seal signature using the public key inside {@code seal.certificate}, after
     * PKIX path-validating that Seal Certificate to {@code trustChain} and binding its Subject to
     * the CNNIC ATI signing identity (ADR 0011).
     *
     * <p>Order of checks: certificate present → SHA-256withRSA allow-list → leaf parses →
     * leaf valid at verification time → leaf chains to the trusted Root → leaf Subject is
     * {@code O=中国互联网络信息中心} + {@code OU=ATI} → signature verifies with the leaf key.
     * Any failure throws, which the caller turns into a seal-verification failure.</p>
     *
     * @param log the transparency log entry
     * @param trustChain the Seal CA Chain to anchor path validation on
     * @return true if the seal signature is valid
     * @throws Exception if verification fails or cannot be performed
     */
    static boolean verifySealWithCertificate(TransparencyLog log, SealTrustChain trustChain) throws Exception {
        Seal seal = log.getSeal();
        if (seal == null || seal.getSignature() == null || seal.getCertificate() == null) {
            throw new IllegalArgumentException("Seal is missing required fields (signature, certificate)");
        }

        requireSha256WithRsa(seal.getSignatureAlgorithm());

        X509Certificate leaf = parseSealCertificate(seal.getCertificate());

        // Seals are signed per-response, so enforce the leaf's validity at verification time.
        leaf.checkValidity();

        // Path-validate leaf → intermediate → root against the injected Seal CA Chain.
        validateCertPath(leaf, trustChain);

        // The Seal CA is shared; bind the leaf Subject to the CNNIC ATI signing identity.
        requireCnnicAtiSubject(leaf);

        return verifySignature(leaf.getPublicKey(), canonicalSignedContent(log), seal.getSignature());
    }

    /**
     * Requires {@code signatureAlgorithm} to be SHA-256withRSA (hyphen-insensitive) per ADR 0009.
     */
    private static void requireSha256WithRsa(String algorithm) {
        if (algorithm == null || algorithm.isBlank()) {
            throw new IllegalArgumentException("Seal signatureAlgorithm is required");
        }
        // Normalize: "SHA-256withRSA" -> "SHA256withRSA" (Java JCA convention)
        String jcaAlgorithm = algorithm.replace("-", "");
        if (!"SHA256withRSA".equals(jcaAlgorithm)) {
            throw new IllegalArgumentException(
                "Seal signatureAlgorithm must be SHA-256withRSA, got: " + algorithm);
        }
    }

    /**
     * Builds and RFC 8785 JCS-canonicalizes the signed content
     * {status, schemaVersion, payload, evidenceRef}.
     */
    private static byte[] canonicalSignedContent(TransparencyLog log) throws Exception {
        Map<String, Object> content = new LinkedHashMap<>();
        content.put("status", log.getStatus());
        content.put("schemaVersion", log.getSchemaVersion());
        content.put("payload", log.getPayload());

        // evidenceRef: use the original JSON map so unknown keys survive JCS
        if (log.getRawEvidenceRef() != null) {
            content.put("evidenceRef", log.getRawEvidenceRef());
        }

        String contentJson = MAPPER.writeValueAsString(content);
        return new JsonCanonicalizer(contentJson).getEncodedUTF8();
    }

    /**
     * Verifies a DER/Base64 SHA-256withRSA signature over the canonicalized content.
     */
    private static boolean verifySignature(PublicKey publicKey, byte[] canonicalBytes, String base64Signature)
            throws Exception {
        byte[] signatureBytes = Base64.getDecoder().decode(base64Signature);
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(publicKey);
        sig.update(canonicalBytes);
        return sig.verify(signatureBytes);
    }

    /**
     * Parses the leaf Seal Certificate from {@code seal.certificate}, which may be a leaf-only PEM
     * or a leaf + intermediate bundle; the leaf is the first certificate.
     */
    private static X509Certificate parseSealCertificate(String pem) {
        // Handle escaped newlines (\n in JSON) before PEM parsing.
        String normalized = pem.replace("\\n", "\n");
        List<X509Certificate> certs = CertificateUtils.parseCertificateChain(normalized);
        return certs.get(0);
    }

    /**
     * PKIX path-validates {@code leaf} → {@code trustChain.intermediate()} against a
     * {@link TrustAnchor} of {@code trustChain.root()}. Revocation checking is disabled (ADR 0011).
     * A wrong or absent anchor, or an expired/not-yet-valid certificate, throws.
     */
    private static void validateCertPath(X509Certificate leaf, SealTrustChain trustChain) throws Exception {
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        CertPath certPath = cf.generateCertPath(List.of(leaf, trustChain.intermediate()));

        PKIXParameters params = new PKIXParameters(Set.of(new TrustAnchor(trustChain.root(), null)));
        params.setRevocationEnabled(false);

        CertPathValidator.getInstance("PKIX").validate(certPath, params);
    }

    /**
     * Requires the leaf Subject to carry {@code O=中国互联网络信息中心} (CNNIC) and {@code OU=ATI}.
     */
    private static void requireCnnicAtiSubject(X509Certificate leaf) {
        X500Name subject = X500Name.getInstance(leaf.getSubjectX500Principal().getEncoded());
        String organization = firstRdnValue(subject, BCStyle.O);
        String organizationalUnit = firstRdnValue(subject, BCStyle.OU);
        if (!EXPECTED_LEAF_ORGANIZATION.equals(organization)
                || !EXPECTED_LEAF_ORGANIZATIONAL_UNIT.equals(organizationalUnit)) {
            throw new IllegalArgumentException(
                "Seal Certificate Subject must be O=" + EXPECTED_LEAF_ORGANIZATION
                    + " + OU=" + EXPECTED_LEAF_ORGANIZATIONAL_UNIT
                    + ", got O=" + organization + " + OU=" + organizationalUnit);
        }
    }

    private static String firstRdnValue(X500Name name, ASN1ObjectIdentifier attributeType) {
        RDN[] rdns = name.getRDNs(attributeType);
        if (rdns.length == 0) {
            return null;
        }
        ASN1Encodable value = rdns[0].getFirst().getValue();
        return value instanceof ASN1String ? ((ASN1String) value).getString() : String.valueOf(value);
    }

    /**
     * Verifies the Merkle inclusion proof from the TL response.
     *
     * @param merkleProof the Merkle proof
     * @return true if the proof is valid
     * @throws Exception if verification fails due to an error
     */
    static boolean verifyMerkleProof(MerkleProof merkleProof) throws Exception {
        if (merkleProof.getLeafHash() == null || merkleProof.getRootHash() == null
                || merkleProof.getLeafIndex() == null || merkleProof.getTreeSize() == null
                || merkleProof.getPath() == null) {
            throw new IllegalArgumentException("MerkleProof is missing required fields");
        }

        byte[] leafHash = MerkleProofVerifier.hexToBytes(merkleProof.getLeafHash());
        long leafIndex = merkleProof.getLeafIndex();
        long treeSize = merkleProof.getTreeSize();
        byte[] rootHash = MerkleProofVerifier.hexToBytes(merkleProof.getRootHash());

        List<byte[]> path = merkleProof.getPath().stream()
            .map(MerkleProofVerifier::hexToBytes)
            .toList();

        return MerkleProofVerifier.verifyInclusionWithHash(
            leafHash, leafIndex, treeSize, path, rootHash);
    }
}
