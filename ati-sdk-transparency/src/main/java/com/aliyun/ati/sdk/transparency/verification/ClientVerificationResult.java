package com.aliyun.ati.sdk.transparency.verification;

import com.aliyun.ati.sdk.transparency.model.TransparencyLog;

import java.util.Objects;

/**
 * Result of verifying a client certificate against the ATI transparency log.
 *
 * <p>This is used when a server wants to verify that a client connecting via
 * mTLS is a registered ATI agent with a valid identity certificate.</p>
 */
public final class ClientVerificationResult {

    private final VerificationStatus status;
    private final TransparencyLog registration;
    private final String expectedIdentityCertFingerprint;
    private final String expectedAtiName;
    private final String expectedAgentHost;
    private final String warningMessage;

    private ClientVerificationResult(Builder builder) {
        this.status = Objects.requireNonNull(builder.status, "status is required");
        this.registration = builder.registration;
        this.expectedIdentityCertFingerprint = builder.expectedIdentityCertFingerprint;
        this.expectedAtiName = builder.expectedAtiName;
        this.expectedAgentHost = builder.expectedAgentHost;
        this.warningMessage = builder.warningMessage;
    }

    /**
     * Returns the verification status.
     *
     * @return the status
     */
    public VerificationStatus getStatus() {
        return status;
    }

    /**
     * Returns the transparency log registration, if found.
     *
     * @return the registration, or null if not found
     */
    public TransparencyLog getRegistration() {
        return registration;
    }

    /**
     * Returns the expected identity certificate fingerprint from the registration.
     *
     * <p>Use this to verify the client's certificate matches what's in the
     * transparency log.</p>
     *
     * @return the expected fingerprint, or null if not available
     */
    public String getExpectedIdentityCertFingerprint() {
        return expectedIdentityCertFingerprint;
    }

    /**
     * Returns the expected ANS name from the registration.
     *
     * <p>Use this to verify the client's certificate URI SAN matches the
     * registration.</p>
     *
     * @return the expected ANS name, or null if not available
     */
    public String getExpectedAtiName() {
        return expectedAtiName;
    }

    /**
     * Returns the expected Identity Hostname from the registration.
     *
     * <p>Derived from {@code payload.agentSubHost} when non-blank, otherwise
     * {@code payload.agentHost}. Not Access Hostname.</p>
     *
     * @return the expected agent host, or null if not available
     */
    public String getExpectedAgentHost() {
        return expectedAgentHost;
    }

    /**
     * Returns a warning message if any issues were detected during verification.
     *
     * @return the warning message, or null if no warnings
     */
    public String getWarningMessage() {
        return warningMessage;
    }

    /**
     * Returns true if the verification was successful.
     *
     * <p>A verification is considered successful if the status is VERIFIED
     * or DEPRECATED_OK.</p>
     *
     * @return true if verification succeeded
     */
    public boolean isSuccess() {
        return status == VerificationStatus.VERIFIED
            || status == VerificationStatus.DEPRECATED_OK;
    }

    /**
     * Returns true if the client is not an ATI agent (no _ati-badge record).
     *
     * @return true if not an ATI agent
     */
    public boolean isNotAtiAgent() {
        return status == VerificationStatus.NOT_ATI_AGENT;
    }

    /**
     * Creates a new builder.
     *
     * @return a new builder
     */
    public static Builder builder() {
        return new Builder();
    }

    @Override
    public String toString() {
        return "ClientVerificationResult{"
            + "status=" + status
            + ", expectedIdentityCertFingerprint='" + expectedIdentityCertFingerprint + '\''
            + ", expectedAtiName='" + expectedAtiName + '\''
            + ", expectedAgentHost='" + expectedAgentHost + '\''
            + ", warningMessage='" + warningMessage + '\''
            + '}';
    }

    /**
     * Builder for ClientVerificationResult.
     */
    public static final class Builder {
        private VerificationStatus status;
        private TransparencyLog registration;
        private String expectedIdentityCertFingerprint;
        private String expectedAtiName;
        private String expectedAgentHost;
        private String warningMessage;

        private Builder() {
        }

        public Builder status(VerificationStatus status) {
            this.status = status;
            return this;
        }

        public Builder registration(TransparencyLog registration) {
            this.registration = registration;
            return this;
        }

        public Builder expectedIdentityCertFingerprint(String fingerprint) {
            this.expectedIdentityCertFingerprint = fingerprint;
            return this;
        }

        public Builder expectedAtiName(String atiName) {
            this.expectedAtiName = atiName;
            return this;
        }

        public Builder expectedAgentHost(String agentHost) {
            this.expectedAgentHost = agentHost;
            return this;
        }

        public Builder warningMessage(String message) {
            this.warningMessage = message;
            return this;
        }

        public ClientVerificationResult build() {
            return new ClientVerificationResult(this);
        }
    }
}