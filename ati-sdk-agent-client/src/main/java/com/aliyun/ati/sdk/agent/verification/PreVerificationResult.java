package com.aliyun.ati.sdk.agent.verification;

import java.util.List;

import com.aliyun.ati.sdk.agent.VerificationPolicy;
import com.aliyun.ati.sdk.discovery.AtiAgentDescriptor;
import com.aliyun.ati.sdk.transparency.verification.ServerVerificationResult;

/**
 * Holds the results of pre-verification (DNS + TL queries) performed
 * before the TLS handshake.
 *
 * <p>After the TLS handshake completes and a server certificate is
 * available, this result is passed to
 * {@link DefaultConnectionVerifier#postVerify} for comparison.
 */
public final class PreVerificationResult {

    private final AtiAgentDescriptor descriptor;
    private final VerificationPolicy policy;
    private final List<DaneTlsaVerifier.TlsaExpectation> daneExpectations;
    private final ServerVerificationResult badgeResult;

    /**
     * Creates a new pre-verification result.
     *
     * @param descriptor       the discovered agent descriptor
     * @param policy           the verification policy
     * @param daneExpectations the DANE TLSA expectations (may be empty)
     * @param badgeResult      the badge TL result (may be null)
     */
    public PreVerificationResult(AtiAgentDescriptor descriptor,
                                 VerificationPolicy policy,
                                 List<DaneTlsaVerifier.TlsaExpectation> daneExpectations,
                                 ServerVerificationResult badgeResult) {
        this.descriptor = descriptor;
        this.policy = policy;
        this.daneExpectations = daneExpectations;
        this.badgeResult = badgeResult;
    }

    /**
     * Returns the discovered agent descriptor.
     *
     * @return the agent descriptor
     */
    public AtiAgentDescriptor getDescriptor() {
        return descriptor;
    }

    /**
     * Returns the verification policy.
     *
     * @return the policy
     */
    public VerificationPolicy getPolicy() {
        return policy;
    }

    /**
     * Returns the DANE TLSA expectations from DNS lookup.
     *
     * @return the TLSA expectations (may be empty)
     */
    public List<DaneTlsaVerifier.TlsaExpectation> getDaneExpectations() {
        return daneExpectations;
    }

    /**
     * Returns the badge TL result from the Transparency Log query.
     *
     * @return the badge result, or {@code null} if badge verification
     *         was disabled or the agent has no agentId
     */
    public ServerVerificationResult getBadgeResult() {
        return badgeResult;
    }
}
