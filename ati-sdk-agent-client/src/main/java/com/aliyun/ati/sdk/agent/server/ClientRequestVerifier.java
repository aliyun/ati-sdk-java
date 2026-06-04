package com.aliyun.ati.sdk.agent.server;

import java.security.cert.X509Certificate;
import java.util.Objects;

import com.aliyun.ati.sdk.agent.verification.IdcaChainVerifier;
import com.aliyun.ati.sdk.agent.verification.VerificationResult;
import com.aliyun.ati.sdk.crypto.CertUtils;
import com.aliyun.ati.sdk.transparency.verification.CachingBadgeVerificationService;
import com.aliyun.ati.sdk.transparency.verification.ClientVerificationResult;
import com.aliyun.ati.sdk.transparency.verification.VerificationStatus;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Verifies inbound client mTLS certificates against the TL registry.
 *
 * <p>Used by an ATI Server to validate that a connecting client's certificate
 * fingerprint matches the expected identity certificate fingerprint recorded
 * in the Transparency Log. The {@code agentId} is passed explicitly; the
 * caller (e.g. a servlet filter or interceptor) is responsible for extracting
 * it from a request header, SAN, or CN.
 */
public final class ClientRequestVerifier {

    private static final Logger LOG = LoggerFactory.getLogger(ClientRequestVerifier.class);

    private final CachingBadgeVerificationService badgeService;
    private final IdcaChainVerifier idcaVerifier;

    /**
     * Creates a verifier with both badge and IDCA verification.
     *
     * @param badgeService the badge verification service (required)
     * @param idcaVerifier the IDCA chain verifier (nullable)
     */
    public ClientRequestVerifier(CachingBadgeVerificationService badgeService,
                                  IdcaChainVerifier idcaVerifier) {
        this.badgeService = Objects.requireNonNull(badgeService, "badgeService must not be null");
        this.idcaVerifier = idcaVerifier; // nullable
    }

    /**
     * Creates a verifier with badge verification only (no IDCA).
     *
     * @param badgeService the badge verification service (required)
     */
    public ClientRequestVerifier(CachingBadgeVerificationService badgeService) {
        this(badgeService, null);
    }

    /**
     * Verifies a client certificate against the TL registry.
     *
     * @param clientCert the client's X.509 certificate from the mTLS handshake
     * @param agentId    the agent identifier (extracted by the caller)
     * @return verification result indicating success or the reason for failure
     */
    public ClientVerificationResult verify(X509Certificate clientCert, String agentId) {
        Objects.requireNonNull(clientCert, "clientCert must not be null");
        Objects.requireNonNull(agentId, "agentId must not be null");

        LOG.debug("Verifying client certificate for agent: {}", agentId);

        ClientVerificationResult tlResult = badgeService.verifyClient(agentId);
        if (tlResult.getStatus() != VerificationStatus.VERIFIED) {
            LOG.warn("Client verification failed for agent {}: {}", agentId, tlResult.getStatus());
            return tlResult;
        }

        String actualFingerprint = CertUtils.sha256Fingerprint(clientCert);
        String expectedFingerprint = tlResult.getIdentityCertFingerprint();

        if (CertUtils.fingerprintMatches(actualFingerprint, expectedFingerprint)) {
            LOG.debug("Client certificate verified for agent {}", agentId);
            return tlResult;
        }

        LOG.warn("Client cert fingerprint mismatch for agent {}: expected={}, actual={}",
            agentId, expectedFingerprint, actualFingerprint);
        return ClientVerificationResult.failed(VerificationStatus.FINGERPRINT_MISMATCH, agentId);
    }

    /**
     * Verifies a client certificate against the IDCA trust chain.
     *
     * @param clientCert the client's X.509 certificate from the mTLS handshake
     * @return verification result indicating success or the reason for failure
     * @deprecated IDCA verification is now handled at the TLS layer via
     *             {@link IdcaChainVerifier#createTrustManager()}. This method
     *             will be removed in a future refactoring.
     */
    @Deprecated
    public VerificationResult verifyIdca(X509Certificate clientCert) {
        Objects.requireNonNull(clientCert, "clientCert must not be null");
        if (idcaVerifier == null) {
            return VerificationResult.failure(VerificationResult.Type.DANE,
                VerificationResult.Status.ERROR,
                "IDCA verifier not configured");
        }
        // IDCA verification is now handled at the TLS layer;
        // this method is a no-op pending removal in Task 4
        return VerificationResult.success(VerificationResult.Type.DANE);
    }
}
