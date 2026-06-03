package com.aliyun.ati.sdk.agent.server;

import java.security.cert.X509Certificate;
import java.util.Objects;

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

    public ClientRequestVerifier(CachingBadgeVerificationService badgeService) {
        this.badgeService = Objects.requireNonNull(badgeService, "badgeService must not be null");
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
}
