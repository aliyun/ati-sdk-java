package com.aliyun.ati.sdk.agent.verification;

import java.security.cert.X509Certificate;
import java.util.Objects;

import com.aliyun.ati.sdk.crypto.CertUtils;
import com.aliyun.ati.sdk.transparency.verification.CachingBadgeVerificationService;
import com.aliyun.ati.sdk.transparency.verification.ServerVerificationResult;
import com.aliyun.ati.sdk.transparency.verification.VerificationStatus;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Verifies an agent's badge from the Transparency Log and compares the
 * expected server certificate fingerprint with the actual certificate.
 */
public final class BadgeVerifier {

    private static final Logger LOG =
        LoggerFactory.getLogger(BadgeVerifier.class);

    private final CachingBadgeVerificationService badgeService;

    /**
     * Creates a new badge verifier.
     *
     * @param badgeService the caching badge verification service
     */
    public BadgeVerifier(CachingBadgeVerificationService badgeService) {
        this.badgeService = Objects.requireNonNull(badgeService,
            "badgeService must not be null");
    }

    /**
     * Verifies the server certificate against the Transparency Log badge.
     *
     * @param agentId    the agent identifier
     * @param serverCert the server certificate presented during TLS handshake
     * @return the verification result
     */
    public VerificationResult verify(String agentId,
                                     X509Certificate serverCert) {
        Objects.requireNonNull(agentId, "agentId must not be null");
        Objects.requireNonNull(serverCert,
            "serverCert must not be null");

        ServerVerificationResult tlResult =
            badgeService.verifyServer(agentId);

        if (tlResult.getStatus() != VerificationStatus.VERIFIED) {
            LOG.warn("Badge verification failed for agent {}: {}",
                agentId, tlResult.getStatus());
            return VerificationResult.failure(
                VerificationResult.Type.BADGE,
                VerificationResult.Status.ERROR,
                tlResult.getStatus().name());
        }

        String actualFingerprint =
            CertUtils.sha256Fingerprint(serverCert);
        String expectedFingerprint =
            tlResult.getServerCertFingerprint();

        if (CertUtils.fingerprintMatches(
                actualFingerprint, expectedFingerprint)) {
            LOG.debug("Badge verification succeeded for agent {}",
                agentId);
            return VerificationResult.success(
                VerificationResult.Type.BADGE);
        }

        LOG.warn("Badge fingerprint mismatch for agent {}: "
                + "expected={}, actual={}",
            agentId, expectedFingerprint, actualFingerprint);
        return VerificationResult.failure(
            VerificationResult.Type.BADGE,
            VerificationResult.Status.MISMATCH,
            "Certificate fingerprint mismatch");
    }
}
