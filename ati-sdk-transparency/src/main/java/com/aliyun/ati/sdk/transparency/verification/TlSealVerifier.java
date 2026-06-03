package com.aliyun.ati.sdk.transparency.verification;

import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;

import com.aliyun.ati.sdk.transparency.model.TransparencyLogResponse;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Verifies the TL seal signature from a {@link TransparencyLogResponse}.
 *
 * <p>Verification steps:
 * <ol>
 *   <li>JCS-canonicalize (RFC 8785) the content fields: status, schemaVersion,
 *       payload, and evidenceRef (excludes seal and merkleProof)</li>
 *   <li>Verify the ECDSA signature using the seal's base64-encoded DER
 *       signature against the canonical bytes with the TL public key</li>
 * </ol>
 */
public final class TlSealVerifier {

    private static final Logger LOG = LoggerFactory.getLogger(TlSealVerifier.class);

    private final ObjectMapper jcsMapper;

    public TlSealVerifier() {
        this.jcsMapper = JsonMapper.builder()
            .configure(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY, true)
            .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true)
            .build();
        this.jcsMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
    }

    /**
     * Verifies the seal signature on the given transparency log response.
     *
     * @param response   the transparency log response to verify
     * @param tlPublicKey the TL server's public key for signature verification
     * @return {@code true} if the signature is valid, {@code false} otherwise
     */
    public boolean verify(TransparencyLogResponse response, PublicKey tlPublicKey) {
        Objects.requireNonNull(response, "response must not be null");
        Objects.requireNonNull(tlPublicKey, "tlPublicKey must not be null");

        try {
            // Build the content to verify (exclude seal and merkleProof)
            Map<String, Object> content = new LinkedHashMap<>();
            content.put("status", response.getStatus());
            content.put("schemaVersion", response.getSchemaVersion());
            content.put("payload", response.getPayload());
            content.put("evidenceRef", response.getEvidenceRef());

            // JCS-canonicalize
            byte[] canonicalBytes = jcsMapper.writeValueAsBytes(content);

            // Decode signature from base64 DER
            String signatureBase64 = response.getSeal().getSignature();
            byte[] signatureBytes = Base64.getDecoder().decode(signatureBase64);

            // Verify ECDSA signature
            Signature sig = Signature.getInstance("SHA256withECDSA");
            sig.initVerify(tlPublicKey);
            sig.update(canonicalBytes);
            boolean valid = sig.verify(signatureBytes);

            if (!valid) {
                LOG.warn("TL seal signature verification failed");
            }
            return valid;
        } catch (Exception e) {
            LOG.error("TL seal verification error", e);
            return false;
        }
    }
}
