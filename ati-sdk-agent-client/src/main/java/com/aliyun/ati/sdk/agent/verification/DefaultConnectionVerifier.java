package com.aliyun.ati.sdk.agent.verification;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import com.aliyun.ati.sdk.agent.VerificationPolicy;
import com.aliyun.ati.sdk.discovery.AtiAgentDescriptor;
import com.aliyun.ati.sdk.transparency.verification.ServerVerificationResult;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Orchestrates DANE and Badge verification against a server certificate
 * based on the configured {@link VerificationPolicy}.
 *
 * <p>The SDK attempts to reach the target level. Failures are returned
 * as {@link VerificationResult} entries — the caller decides whether
 * to accept or reject based on the achieved results.
 */
public final class DefaultConnectionVerifier {

    private static final Logger LOG =
        LoggerFactory.getLogger(DefaultConnectionVerifier.class);

    private final DaneTlsaVerifier daneVerifier;
    private final BadgeVerifier badgeVerifier;

    public DefaultConnectionVerifier(DaneTlsaVerifier daneVerifier,
                                     BadgeVerifier badgeVerifier) {
        this.daneVerifier = Objects.requireNonNull(daneVerifier,
            "daneVerifier must not be null");
        this.badgeVerifier = Objects.requireNonNull(badgeVerifier,
            "badgeVerifier must not be null");
    }

    /**
     * Pre-verifies by querying DNS (DANE) and the Transparency Log
     * (Badge) without performing a TLS handshake.
     */
    public PreVerificationResult preVerify(
            AtiAgentDescriptor descriptor,
            VerificationPolicy policy,
            int port) {
        Objects.requireNonNull(descriptor, "descriptor must not be null");
        Objects.requireNonNull(policy, "policy must not be null");

        List<DaneTlsaVerifier.TlsaExpectation> daneExpectations = List.of();
        ServerVerificationResult badgeResult = null;

        if (policy.ordinal() >= VerificationPolicy.SILVER.ordinal()) {
            try {
                daneExpectations = daneVerifier.getTlsaExpectations(
                    descriptor.getAgentHost(), port);
            } catch (Exception e) {
                LOG.warn("DANE pre-verify failed: {}", e.getMessage());
            }
        }

        if (policy == VerificationPolicy.GOLD
                && descriptor.getAgentId() != null) {
            try {
                badgeResult = badgeVerifier.preVerify(
                    descriptor.getAgentId());
            } catch (Exception e) {
                LOG.warn("Badge pre-verify failed: {}", e.getMessage());
            }
        }

        return new PreVerificationResult(
            descriptor, policy, daneExpectations, badgeResult);
    }

    /**
     * Post-verifies the server certificate against pre-fetched expectations.
     * Returns results without throwing — the caller decides how to handle.
     */
    public List<VerificationResult> postVerify(
            X509Certificate serverCert,
            PreVerificationResult preResult) {
        Objects.requireNonNull(serverCert, "serverCert must not be null");
        Objects.requireNonNull(preResult, "preResult must not be null");

        List<VerificationResult> results = new ArrayList<>();
        VerificationPolicy policy = preResult.getPolicy();

        if (policy.ordinal() >= VerificationPolicy.SILVER.ordinal()) {
            VerificationResult daneResult = daneVerifier.postVerify(
                serverCert, preResult.getDaneExpectations());
            results.add(daneResult);
            if (!daneResult.isSuccess()) {
                LOG.warn("DANE verification failed: {}",
                    daneResult.getDetail());
            }
        }

        if (policy == VerificationPolicy.GOLD
                && preResult.getBadgeResult() != null) {
            VerificationResult badgeResult = badgeVerifier.postVerify(
                serverCert, preResult.getBadgeResult());
            results.add(badgeResult);
            if (!badgeResult.isSuccess()) {
                LOG.warn("Badge verification failed: {}",
                    badgeResult.getDetail());
            }
        }

        return Collections.unmodifiableList(results);
    }
}
