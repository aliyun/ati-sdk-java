package com.aliyun.ati.sdk.transparency.verification;

import java.util.Objects;

/**
 * Immutable result of a server-side badge verification.
 *
 * <p>Contains the verification status, the server certificate fingerprint
 * (only set when {@link VerificationStatus#VERIFIED}), and the agent ID.
 */
public final class ServerVerificationResult {

    private final VerificationStatus status;
    private final String serverCertFingerprint;
    private final String agentId;

    private ServerVerificationResult(VerificationStatus status,
                                     String serverCertFingerprint,
                                     String agentId) {
        this.status = Objects.requireNonNull(status, "status must not be null");
        this.serverCertFingerprint = serverCertFingerprint;
        this.agentId = agentId;
    }

    /**
     * Creates a verified result with a server certificate fingerprint.
     *
     * @param serverCertFingerprint the SHA-256 fingerprint of the server certificate
     * @param agentId               the agent identifier
     * @return a verified result
     */
    public static ServerVerificationResult verified(String serverCertFingerprint, String agentId) {
        return new ServerVerificationResult(VerificationStatus.VERIFIED, serverCertFingerprint, agentId);
    }

    /**
     * Creates a failed result with the given status.
     *
     * @param status  the failure reason
     * @param agentId the agent identifier (may be null)
     * @return a failed result
     */
    public static ServerVerificationResult failed(VerificationStatus status, String agentId) {
        return new ServerVerificationResult(status, null, agentId);
    }

    public VerificationStatus getStatus() {
        return status;
    }

    public String getServerCertFingerprint() {
        return serverCertFingerprint;
    }

    public String getAgentId() {
        return agentId;
    }

    @Override
    public String toString() {
        return "ServerVerificationResult{"
            + "status=" + status
            + ", serverCertFingerprint='" + serverCertFingerprint + '\''
            + ", agentId='" + agentId + '\''
            + '}';
    }
}
