package com.aliyun.ati.sdk.transparency.verification;

import java.util.Objects;

/**
 * Immutable result of a client-side badge verification.
 *
 * <p>Contains the verification status, the identity certificate fingerprint
 * (only set when {@link VerificationStatus#VERIFIED}), agent host, and agent ID.
 */
public final class ClientVerificationResult {

    private final VerificationStatus status;
    private final String identityCertFingerprint;
    private final String agentHost;
    private final String agentId;

    private ClientVerificationResult(VerificationStatus status,
                                     String identityCertFingerprint,
                                     String agentHost,
                                     String agentId) {
        this.status = Objects.requireNonNull(status, "status must not be null");
        this.identityCertFingerprint = identityCertFingerprint;
        this.agentHost = agentHost;
        this.agentId = agentId;
    }

    /**
     * Creates a verified result with an identity certificate fingerprint.
     *
     * @param identityCertFingerprint the SHA-256 fingerprint of the identity certificate
     * @param agentHost               the agent host name
     * @param agentId                 the agent identifier
     * @return a verified result
     */
    public static ClientVerificationResult verified(String identityCertFingerprint,
                                                     String agentHost,
                                                     String agentId) {
        return new ClientVerificationResult(
            VerificationStatus.VERIFIED, identityCertFingerprint, agentHost, agentId);
    }

    /**
     * Creates a failed result with the given status.
     *
     * @param status  the failure reason
     * @param agentId the agent identifier (may be null)
     * @return a failed result
     */
    public static ClientVerificationResult failed(VerificationStatus status, String agentId) {
        return new ClientVerificationResult(status, null, null, agentId);
    }

    public VerificationStatus getStatus() {
        return status;
    }

    public String getIdentityCertFingerprint() {
        return identityCertFingerprint;
    }

    public String getAgentHost() {
        return agentHost;
    }

    public String getAgentId() {
        return agentId;
    }

    @Override
    public String toString() {
        return "ClientVerificationResult{"
            + "status=" + status
            + ", identityCertFingerprint='" + identityCertFingerprint + '\''
            + ", agentHost='" + agentHost + '\''
            + ", agentId='" + agentId + '\''
            + '}';
    }
}
