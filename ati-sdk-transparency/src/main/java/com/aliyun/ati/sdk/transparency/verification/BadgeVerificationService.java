package com.aliyun.ati.sdk.transparency.verification;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Objects;

import com.aliyun.ati.sdk.transparency.AtiTransparencyClient;
import com.aliyun.ati.sdk.transparency.model.TransparencyLogResponse;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Orchestrates badge verification by combining TL lookup, seal verification,
 * and Merkle proof verification into a single verification flow.
 *
 * <p>This service is the main entry point for verifying an agent's badge.
 * It can be wrapped by {@code CachingBadgeVerificationService} to add caching.
 */
public final class BadgeVerificationService {

    private static final Logger LOG = LoggerFactory.getLogger(BadgeVerificationService.class);

    private final AtiTransparencyClient transparencyClient;
    private final TlSealVerifier sealVerifier;
    private final MerkleProofVerifier merkleVerifier;

    public BadgeVerificationService(AtiTransparencyClient transparencyClient,
                                     TlSealVerifier sealVerifier,
                                     MerkleProofVerifier merkleVerifier) {
        this.transparencyClient = Objects.requireNonNull(
            transparencyClient, "transparencyClient must not be null");
        this.sealVerifier = Objects.requireNonNull(
            sealVerifier, "sealVerifier must not be null");
        this.merkleVerifier = Objects.requireNonNull(
            merkleVerifier, "merkleVerifier must not be null");
    }

    public ServerVerificationResult verifyServer(String agentId) {
        Objects.requireNonNull(agentId, "agentId must not be null");
        try {
            TransparencyLogResponse response = transparencyClient.getLatestLog(agentId);

            if (!"ACTIVE".equals(response.getStatus())) {
                LOG.warn("Agent {} is not active: {}", agentId, response.getStatus());
                return ServerVerificationResult.failed(VerificationStatus.AGENT_REVOKED, agentId);
            }

            PublicKey tlKey = parseSealPublicKey(response.getSeal().getPublicKey());

            if (!sealVerifier.verify(response, tlKey)) {
                LOG.warn("Seal verification failed for agent {}", agentId);
                return ServerVerificationResult.failed(VerificationStatus.SEAL_INVALID, agentId);
            }

            if (!merkleVerifier.verify(response.getMerkleProof())) {
                LOG.warn("Merkle proof verification failed for agent {}", agentId);
                return ServerVerificationResult.failed(
                    VerificationStatus.MERKLE_PROOF_INVALID, agentId);
            }

            String fingerprint = response.getPayload().getCertificates().getServerCertFingerprint();
            return ServerVerificationResult.verified(fingerprint, agentId);
        } catch (Exception e) {
            LOG.error("Badge verification failed for agent {}", agentId, e);
            return ServerVerificationResult.failed(VerificationStatus.LOOKUP_FAILED, agentId);
        }
    }

    public ClientVerificationResult verifyClient(String agentId) {
        Objects.requireNonNull(agentId, "agentId must not be null");
        try {
            TransparencyLogResponse response = transparencyClient.getLatestLog(agentId);

            if (!"ACTIVE".equals(response.getStatus())) {
                LOG.warn("Agent {} is not active: {}", agentId, response.getStatus());
                return ClientVerificationResult.failed(VerificationStatus.AGENT_REVOKED, agentId);
            }

            PublicKey tlKey = parseSealPublicKey(response.getSeal().getPublicKey());

            if (!sealVerifier.verify(response, tlKey)) {
                LOG.warn("Seal verification failed for agent {}", agentId);
                return ClientVerificationResult.failed(VerificationStatus.SEAL_INVALID, agentId);
            }

            if (!merkleVerifier.verify(response.getMerkleProof())) {
                LOG.warn("Merkle proof verification failed for agent {}", agentId);
                return ClientVerificationResult.failed(
                    VerificationStatus.MERKLE_PROOF_INVALID, agentId);
            }

            String fingerprint = response.getPayload()
                .getCertificates().getIdentityCertFingerprint();
            String agentHost = response.getPayload().getAgentHost();
            return ClientVerificationResult.verified(fingerprint, agentHost, agentId);
        } catch (Exception e) {
            LOG.error("Client badge verification failed for agent {}", agentId, e);
            return ClientVerificationResult.failed(VerificationStatus.LOOKUP_FAILED, agentId);
        }
    }

    private static PublicKey parseSealPublicKey(String pem) throws Exception {
        String base64 = pem
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replaceAll("\\s+", "");
        byte[] decoded = Base64.getDecoder().decode(base64);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);
        return KeyFactory.getInstance("EC").generatePublic(keySpec);
    }
}
