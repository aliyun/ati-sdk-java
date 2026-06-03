package com.aliyun.ati.sdk.agent.verification;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import com.aliyun.ati.sdk.agent.VerificationMode;
import com.aliyun.ati.sdk.agent.VerificationPolicy;
import com.aliyun.ati.sdk.discovery.AtiAgentDescriptor;
import com.aliyun.ati.sdk.exception.AtiException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Orchestrates DANE, Badge and IDCA verification against a server certificate
 * based on the configured {@link VerificationPolicy}.
 *
 * <p>Respects {@link VerificationMode}:
 * <ul>
 *   <li>DISABLED — skip verification</li>
 *   <li>ADVISORY — run verification, log warning on failure</li>
 *   <li>REQUIRED — run verification, throw on failure</li>
 * </ul>
 */
public final class DefaultConnectionVerifier {

    private static final Logger LOG =
        LoggerFactory.getLogger(DefaultConnectionVerifier.class);

    private final DaneTlsaVerifier daneVerifier;
    private final BadgeVerifier badgeVerifier;
    private final IdcaChainVerifier idcaVerifier;

    /**
     * Creates a new connection verifier with IDCA support.
     *
     * @param daneVerifier  the DANE TLSA verifier
     * @param badgeVerifier the badge verifier
     * @param idcaVerifier  the IDCA chain verifier (nullable)
     */
    public DefaultConnectionVerifier(DaneTlsaVerifier daneVerifier,
                                     BadgeVerifier badgeVerifier,
                                     IdcaChainVerifier idcaVerifier) {
        this.daneVerifier = Objects.requireNonNull(daneVerifier,
            "daneVerifier must not be null");
        this.badgeVerifier = Objects.requireNonNull(badgeVerifier,
            "badgeVerifier must not be null");
        this.idcaVerifier = idcaVerifier; // nullable
    }

    /**
     * Creates a new connection verifier without IDCA support.
     *
     * @param daneVerifier  the DANE TLSA verifier
     * @param badgeVerifier the badge verifier
     */
    public DefaultConnectionVerifier(DaneTlsaVerifier daneVerifier,
                                     BadgeVerifier badgeVerifier) {
        this(daneVerifier, badgeVerifier, null);
    }

    /**
     * Verifies the server certificate using DANE, Badge and/or IDCA verification
     * according to the given policy.
     *
     * @param descriptor the agent descriptor from discovery
     * @param serverCert the server certificate from the TLS handshake
     * @param policy     the verification policy
     * @return an unmodifiable list of verification results
     * @throws AtiException if a REQUIRED verification fails
     */
    public List<VerificationResult> verify(
            AtiAgentDescriptor descriptor,
            X509Certificate serverCert,
            VerificationPolicy policy) {
        Objects.requireNonNull(descriptor,
            "descriptor must not be null");
        Objects.requireNonNull(serverCert,
            "serverCert must not be null");
        Objects.requireNonNull(policy, "policy must not be null");

        List<VerificationResult> results = new ArrayList<>();

        if (policy.getDaneMode() != VerificationMode.DISABLED) {
            VerificationResult daneResult = daneVerifier.verify(
                descriptor.getAgentHost(), 443, serverCert);
            results.add(daneResult);
            handleResult(daneResult, policy.getDaneMode(), "DANE");
        }

        if (policy.getBadgeMode() != VerificationMode.DISABLED
                && descriptor.getAgentId() != null) {
            VerificationResult badgeResult = badgeVerifier.verify(
                descriptor.getAgentId(), serverCert);
            results.add(badgeResult);
            handleResult(badgeResult, policy.getBadgeMode(), "Badge");
        }

        if (policy.getIdcaMode() != VerificationMode.DISABLED) {
            if (idcaVerifier != null) {
                VerificationResult idcaResult = idcaVerifier.verify(serverCert);
                results.add(idcaResult);
                handleResult(idcaResult, policy.getIdcaMode(), "IDCA");
            } else {
                LOG.warn("IDCA verification requested (mode={}) "
                    + "but no IdcaChainVerifier configured; skipping",
                    policy.getIdcaMode());
            }
        }

        return Collections.unmodifiableList(results);
    }

    private void handleResult(VerificationResult result,
                              VerificationMode mode, String type) {
        if (result.isSuccess()) {
            return;
        }
        if (mode == VerificationMode.REQUIRED) {
            throw new AtiException(
                type + " verification failed: " + result.getDetail());
        }
        if (mode == VerificationMode.ADVISORY) {
            LOG.warn("{} verification failed (advisory): {}",
                type, result.getDetail());
        }
    }
}
