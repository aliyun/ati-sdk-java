package com.aliyun.ati.sdk.transparency.verification;

import com.aliyun.ati.sdk.transparency.model.MerkleProof;
import com.aliyun.ati.sdk.transparency.model.Seal;
import com.aliyun.ati.sdk.transparency.model.TransparencyLog;
import com.aliyun.ati.sdk.transparency.scitt.MerkleProofVerifier;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.erdtman.jcs.JsonCanonicalizer;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

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
     * Verifies both the seal signature and Merkle inclusion proof of a TL response.
     *
     * <p>If the response has no seal or merkle data (e.g., legacy TL format),
     * verification is skipped and the result is considered valid for backwards compatibility.</p>
     *
     * @param log the transparency log response to verify
     * @return the verification result
     */
    public static VerificationResult verify(TransparencyLog log) {
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
                sealValid = verifySeal(log);
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
     * Verifies the seal signature over the canonicalized content.
     *
     * <p>The signed content is: {status, schemaVersion, payload, evidenceRef}
     * canonicalized using RFC 8785 JCS, then verified with SHA-256withRSA.</p>
     *
     * @param log the transparency log entry
     * @return true if the seal signature is valid
     * @throws Exception if verification fails due to an error
     */
    static boolean verifySeal(TransparencyLog log) throws Exception {
        Seal seal = log.getSeal();
        if (seal == null || seal.getSignature() == null || seal.getPublicKey() == null) {
            throw new IllegalArgumentException("Seal is missing required fields (signature, publicKey)");
        }

        String algorithm = seal.getSignatureAlgorithm();
        if (algorithm == null || algorithm.isBlank()) {
            throw new IllegalArgumentException("Seal signatureAlgorithm is required");
        }
        // Normalize: "SHA-256withRSA" -> "SHA256withRSA" (Java JCA convention)
        String jcaAlgorithm = algorithm.replace("-", "");
        if (!"SHA256withRSA".equals(jcaAlgorithm)) {
            throw new IllegalArgumentException(
                "Seal signatureAlgorithm must be SHA-256withRSA, got: " + algorithm);
        }

        PublicKey publicKey = parsePublicKey(seal.getPublicKey());

        // Build the content that was signed: {status, schemaVersion, payload, evidenceRef}
        Map<String, Object> content = new LinkedHashMap<>();
        content.put("status", log.getStatus());
        content.put("schemaVersion", log.getSchemaVersion());
        content.put("payload", log.getPayload());

        // evidenceRef: use the original JSON map so unknown keys survive JCS
        if (log.getRawEvidenceRef() != null) {
            content.put("evidenceRef", log.getRawEvidenceRef());
        }

        // JCS canonicalize (RFC 8785)
        String contentJson = MAPPER.writeValueAsString(content);
        JsonCanonicalizer canonicalizer = new JsonCanonicalizer(contentJson);
        byte[] canonicalBytes = canonicalizer.getEncodedUTF8();

        byte[] signatureBytes = Base64.getDecoder().decode(seal.getSignature());
        Signature sig = Signature.getInstance("SHA256withRSA");
        sig.initVerify(publicKey);
        sig.update(canonicalBytes);

        return sig.verify(signatureBytes);
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

    /**
     * Parses a PEM-encoded public key.
     *
     * @param pem the PEM string (may contain escaped newlines)
     * @return the parsed public key
     * @throws Exception if parsing fails
     */
    private static PublicKey parsePublicKey(String pem) throws Exception {
        // Handle both real newlines and escaped newlines (\\n in JSON)
        String normalized = pem.replace("\\n", "\n");
        String base64Key = normalized
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replaceAll("\\s+", "");
        byte[] keyBytes = Base64.getDecoder().decode(base64Key);
        return KeyFactory.getInstance("RSA")
            .generatePublic(new X509EncodedKeySpec(keyBytes));
    }
}
