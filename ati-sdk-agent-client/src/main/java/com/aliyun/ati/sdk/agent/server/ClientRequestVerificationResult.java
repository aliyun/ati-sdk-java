package com.aliyun.ati.sdk.agent.server;

import com.aliyun.ati.sdk.agent.VerificationPolicy;

import java.time.Duration;
import java.util.List;
import java.util.Objects;

/**
 * Result of client request verification.
 *
 * <p>Contains the outcome of verifying an incoming client request against
 * ATI Badge and/or DANE records, including the extracted agent identity
 * and any errors encountered.</p>
 *
 * @param verified true if the client was successfully verified
 * @param agentId the agent ID from the transparency log (null if not available)
 * @param agentHost the agent hostname extracted from the certificate URI SAN
 *                  (e.g., "client-agent.example.com")
 * @param errors list of error messages (empty if verification succeeded)
 * @param policyUsed the verification policy that was applied
 * @param verificationDuration how long verification took
 */
public record ClientRequestVerificationResult(
    boolean verified,
    String agentId,
    String agentHost,
    List<String> errors,
    VerificationPolicy policyUsed,
    Duration verificationDuration
) {

    /**
     * Compact constructor for defensive copying and validation.
     */
    public ClientRequestVerificationResult {
        Objects.requireNonNull(errors, "errors cannot be null");
        Objects.requireNonNull(policyUsed, "policyUsed cannot be null");
        Objects.requireNonNull(verificationDuration, "verificationDuration cannot be null");
        errors = List.copyOf(errors);
    }

    /**
     * Creates a successful verification result.
     *
     * @param agentId the verified agent ID (may be null for PKI_ONLY)
     * @param agentHost the agent hostname from the certificate URI SAN
     * @param policy the policy that was used
     * @param duration how long verification took
     * @return a successful result
     */
    public static ClientRequestVerificationResult success(
            String agentId,
            String agentHost,
            VerificationPolicy policy,
            Duration duration) {
        return new ClientRequestVerificationResult(
            true,
            agentId,
            agentHost,
            List.of(),
            policy,
            duration
        );
    }

    /**
     * Creates a failed verification result with multiple errors.
     *
     * @param errors the error messages
     * @param agentHost the agent hostname if extracted (may be null)
     * @param policy the policy that was used
     * @param duration how long verification took
     * @return a failed result
     */
    public static ClientRequestVerificationResult failure(
            List<String> errors,
            String agentHost,
            VerificationPolicy policy,
            Duration duration) {
        return new ClientRequestVerificationResult(
            false,
            null,
            agentHost,
            errors,
            policy,
            duration
        );
    }

    /**
     * Creates a failed verification result with a single error.
     *
     * @param error the error message
     * @param agentHost the agent hostname if extracted (may be null)
     * @param policy the policy that was used
     * @param duration how long verification took
     * @return a failed result
     */
    public static ClientRequestVerificationResult failure(
            String error,
            String agentHost,
            VerificationPolicy policy,
            Duration duration) {
        return failure(
            List.of(error),
            agentHost,
            policy,
            duration
        );
    }

    @Override
    public String toString() {
        if (verified) {
            return String.format(
                "ClientRequestVerificationResult{verified=true, agentId='%s', agentHost='%s', policy=%s, duration=%s}",
                agentId, agentHost, policyUsed, verificationDuration);
        } else {
            return String.format(
                "ClientRequestVerificationResult{verified=false, agentHost='%s', errors=%s, policy=%s, duration=%s}",
                agentHost, errors, policyUsed, verificationDuration);
        }
    }
}
