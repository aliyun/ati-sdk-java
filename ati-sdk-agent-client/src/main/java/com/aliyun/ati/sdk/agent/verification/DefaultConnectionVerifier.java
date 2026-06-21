package com.aliyun.ati.sdk.agent.verification;

import com.aliyun.ati.sdk.agent.VerificationPolicy;
import com.aliyun.ati.sdk.transparency.TransparencyClient;
import com.aliyun.ati.sdk.transparency.scitt.ScittPreVerifyResult;
import com.aliyun.ati.sdk.transparency.verification.CachingBadgeVerificationService;
import com.aliyun.ati.sdk.transparency.verification.ServerVerifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;

/**
 * Default implementation of {@link ConnectionVerifier} that composes DANE and Badge verifiers.
 *
 * <p>This implementation performs verification outside the TLS handshake:</p>
 * <ol>
 *   <li><b>Pre-verification</b>: Runs all enabled verifiers in parallel to gather expectations</li>
 *   <li><b>Post-verification</b>: Compares actual certificate against expectations</li>
 * </ol>
 *
 * <h2>Usage</h2>
 * <pre>{@code
 * DefaultConnectionVerifier verifier = DefaultConnectionVerifier.builder()
 *     .daneVerifier(new DaneVerifier(tlsaVerifier))
 *     .badgeVerifier(new BadgeVerifier(verificationService))
 *     .build();
 *
 * // Pre-verify (async, cacheable)
 * PreVerificationResult preResult = verifier.preVerify("example.com", 443).join();
 *
 * // ... TLS handshake happens with PKI-only validation ...
 *
 * // Post-verify (fast fingerprint comparison)
 * List<VerificationResult> results = verifier.postVerify("example.com", serverCert, preResult);
 *
 * // Check combined result
 * VerificationResult combined = verifier.combine(results, policy);
 * if (combined.shouldFail()) {
 *     throw new VerificationException(combined);
 * }
 * }</pre>
 */
public class DefaultConnectionVerifier implements ConnectionVerifier {

    private static final Logger LOGGER = LoggerFactory.getLogger(DefaultConnectionVerifier.class);

    private final DaneVerifier daneVerifier;
    private final BadgeVerifier badgeVerifier;
    private final ScittVerifierAdapter scittVerifier;

    private DefaultConnectionVerifier(Builder builder) {
        this.daneVerifier = builder.daneVerifier;
        this.badgeVerifier = builder.badgeVerifier;
        this.scittVerifier = builder.scittVerifier;
    }

    /**
     * Creates a new builder.
     *
     * @return a new builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Creates a DefaultConnectionVerifier from a verification policy.
     *
     * <p>Wires DANE, Badge, and SCITT verifiers based on which modes are enabled
     * in the policy. This is the recommended way to construct a verifier when
     * you don't need custom caching or service overrides.</p>
     *
     * @param policy the verification policy controlling which verifiers are enabled
     * @param transparencyClient the transparency client for SCITT verification, or null
     * @param daneVerifier the DANE TLSA verifier, or null to skip DANE regardless of policy
     * @return a configured verifier
     */
    public static DefaultConnectionVerifier fromPolicy(
            VerificationPolicy policy,
            TransparencyClient transparencyClient,
            DaneTlsaVerifier daneVerifier) {
        return fromPolicy(policy, transparencyClient, daneVerifier, null);
    }

    /**
     * Creates a DefaultConnectionVerifier from a verification policy with an optional
     * badge service override.
     *
     * <p>Use the {@code badgeServiceOverride} parameter when you need to share a cached
     * badge verification service across multiple verifier instances (e.g., in a factory
     * that creates verifiers per-connection).</p>
     *
     * @param policy the verification policy controlling which verifiers are enabled
     * @param transparencyClient the transparency client for SCITT verification, or null
     * @param daneVerifier the DANE TLSA verifier, or null to skip DANE regardless of policy
     * @param badgeServiceOverride optional pre-built badge service; if null, a new
     *                             {@link CachingBadgeVerificationService} is created
     * @return a configured verifier
     */
    public static DefaultConnectionVerifier fromPolicy(
            VerificationPolicy policy,
            TransparencyClient transparencyClient,
            DaneTlsaVerifier daneVerifier,
            ServerVerifier badgeServiceOverride) {
        Builder builder = builder();

        if (policy.hasDaneVerification() && daneVerifier != null) {
            builder.daneVerifier(new DaneVerifier(daneVerifier));
        }

        if (policy.hasBadgeVerification()) {
            ServerVerifier badgeService;
            if (badgeServiceOverride != null) {
                badgeService = badgeServiceOverride;
            } else if (transparencyClient != null) {
                badgeService = CachingBadgeVerificationService.create(transparencyClient);
            } else {
                throw new IllegalStateException(
                    "Badge verification is enabled but no TransparencyClient or badge service "
                    + "was provided. Supply a TransparencyClient with an explicit baseUrl.");
            }
            builder.badgeVerifier(new BadgeVerifier(badgeService));
        }

        // SCITT is not enabled by any simplified policy value - skip SCITT verifier setup

        return builder.build();
    }

    @Override
    public CompletableFuture<PreVerificationResult> preVerify(String hostname, int port) {
        LOGGER.debug("Pre-verifying {}:{}", hostname, port);

        // Run all pre-verifications in parallel
        CompletableFuture<DaneVerifier.PreVerifyResult> daneFuture = daneVerifier != null
            ? daneVerifier.preVerify(hostname, port)
            : CompletableFuture.completedFuture(DaneVerifier.PreVerifyResult.success(List.of()));

        CompletableFuture<BadgeVerifier.BadgeExpectation> badgeFuture = badgeVerifier != null
            ? badgeVerifier.preVerify(hostname)
            : CompletableFuture.completedFuture(null);

        // Combine results
        return daneFuture.thenCombine(badgeFuture, (daneResult, badge) -> {
                PreVerificationResult.Builder builder = PreVerificationResult.builder(hostname, port);

                // Add DANE expectations and DNS error status
                builder.danePreVerifyResult(daneResult);

                // Add Badge expectation(s)
                if (badge != null) {
                    if (badge.isRegisteredAgent()) {
                        // During version rotation, multiple badge records may exist
                        builder.badgeFingerprints(badge.expectedFingerprints());
                    } else if (badge.preVerificationFailed()) {
                        // Capture pre-verification failure (e.g., revoked/expired registration)
                        builder.badgePreVerifyFailed(badge.warningMessage());
                    }
                }

                PreVerificationResult result = builder.build();
                LOGGER.debug("Pre-verification complete for {}:{}: {}", hostname, port, result);
                return result;
            });
    }

    @Override
    public CompletableFuture<ScittPreVerifyResult> scittPreVerify(Map<String, String> responseHeaders) {
        if (scittVerifier == null) {
            return CompletableFuture.completedFuture(ScittPreVerifyResult.notPresent());
        }
        return scittVerifier.preVerify(responseHeaders);
    }

    @Override
    public List<VerificationResult> postVerify(String hostname, X509Certificate serverCert,
                                                PreVerificationResult preResult) {
        LOGGER.debug("Post-verifying {} with certificate", hostname);

        List<VerificationResult> results = new ArrayList<>();

        postVerifyDane(hostname, serverCert, preResult).ifPresent(results::add);
        postVerifyScitt(hostname, serverCert, preResult).ifPresent(results::add);
        postVerifyBadge(hostname, serverCert, preResult).ifPresent(results::add);

        return results;
    }

    /**
     * Performs DANE post-verification if DANE verifier is configured.
     */
    private Optional<VerificationResult> postVerifyDane(String hostname,
                                                                   X509Certificate serverCert,
                                                                   PreVerificationResult preResult) {
        if (daneVerifier == null) {
            return Optional.empty();
        }

        VerificationResult daneResult;
        if (preResult.daneDnsError()) {
            // DNS query failed - this is an ERROR, not NOT_FOUND
            daneResult = VerificationResult.error(
                VerificationResult.VerificationType.DANE,
                "DNS lookup failed: " + preResult.daneDnsErrorMessage());
            LOGGER.warn("DANE DNS error for {}: {}", hostname, preResult.daneDnsErrorMessage());
        } else {
            daneResult = daneVerifier.postVerify(hostname, serverCert, preResult.daneExpectations());
        }

        LOGGER.debug("DANE result for {}: {}", hostname, daneResult.status());
        return Optional.of(daneResult);
    }

    /**
     * Performs SCITT post-verification if SCITT verifier is configured.
     */
    private Optional<VerificationResult> postVerifyScitt(String hostname,
                                                                    X509Certificate serverCert,
                                                                    PreVerificationResult preResult) {
        if (scittVerifier == null) {
            return Optional.empty();
        }

        VerificationResult scittResult;
        if (preResult.hasScittExpectation()) {
            scittResult = scittVerifier.postVerify(hostname, serverCert, preResult.scittPreVerifyResult());
        } else {
            // SCITT verifier present but no SCITT artifacts in response
            scittResult = VerificationResult.notFound(
                VerificationResult.VerificationType.SCITT,
                "SCITT headers not present in response");
        }

        LOGGER.debug("SCITT result for {}: {}", hostname, scittResult.status());
        return Optional.of(scittResult);
    }

    /**
     * Performs Badge post-verification if Badge verifier is configured.
     */
    private Optional<VerificationResult> postVerifyBadge(String hostname,
                                                                    X509Certificate serverCert,
                                                                    PreVerificationResult preResult) {
        if (badgeVerifier == null) {
            return Optional.empty();
        }

        BadgeVerifier.BadgeExpectation badgeExpectation = buildBadgeExpectation(preResult);
        VerificationResult badgeResult = badgeVerifier.postVerify(hostname, serverCert, badgeExpectation);

        LOGGER.debug("Badge result for {}: {}", hostname, badgeResult.status());
        return Optional.of(badgeResult);
    }

    /**
     * Builds the badge expectation from the pre-verification result.
     */
    private BadgeVerifier.BadgeExpectation buildBadgeExpectation(PreVerificationResult preResult) {
        if (preResult.badgePreVerifyFailed()) {
            // Pre-verification failed (e.g., revoked/expired registration)
            return BadgeVerifier.BadgeExpectation.failed(preResult.badgeFailureReason());
        } else if (preResult.hasBadgeExpectation()) {
            // During version rotation, multiple fingerprints may exist
            return BadgeVerifier.BadgeExpectation.registered(preResult.badgeFingerprints(), false, null);
        } else {
            return BadgeVerifier.BadgeExpectation.notAtiAgent();
        }
    }

    @Override
    public VerificationResult combine(List<VerificationResult> results, VerificationPolicy policy) {
        LOGGER.debug("Combining {} verification results with policy {}", results.size(), policy);

        // Check for failures - all enabled verifications are REQUIRED in progressive model
        VerificationResult failure = checkForFailures(results, policy);
        if (failure != null) {
            return failure;
        }

        // All required verifications passed - return the best success result
        return selectSuccessResult(results);
    }

    /**
     * Checks all results for failures based on policy.
     *
     * <p>In the progressive model, all enabled verifications are REQUIRED.
     * Any failure or NOT_FOUND for an enabled verification type causes overall failure.</p>
     *
     * @return the first failure result, or null if no failures
     */
    private VerificationResult checkForFailures(List<VerificationResult> results,
                                                 VerificationPolicy policy) {
        for (VerificationResult result : results) {
            // Check if this verification type is enabled in the policy
            boolean isEnabled = isVerificationEnabled(result.type(), policy);
            if (!isEnabled) {
                continue;
            }

            // All enabled verifications are REQUIRED - any failure is fatal
            if (result.shouldFail()) {
                LOGGER.warn("Verification failed (REQUIRED): {}", result);
                return result;
            }

            // NOT_FOUND for an enabled verification type is also a failure
            if (result.isNotFound()) {
                LOGGER.warn("Verification not found but REQUIRED: {}", result);
                return VerificationResult.error(
                    result.type(),
                    "No " + result.type().name().toLowerCase()
                        + " record/registration found for verification (REQUIRED)");
            }
        }
        return null;
    }

    /**
     * Returns whether a verification type is enabled in the given policy.
     */
    private boolean isVerificationEnabled(VerificationResult.VerificationType type,
                                           VerificationPolicy policy) {
        return switch (type) {
            case DANE -> policy.hasDaneVerification();
            case BADGE -> policy.hasBadgeVerification();
            case SCITT -> false; // SCITT is not exposed in simplified policy
            case PKI_ONLY -> false;
        };
    }

    /**
     * Selects the best success result based on priority: Badge > DANE.
     */
    private VerificationResult selectSuccessResult(List<VerificationResult> results) {
        return findSuccessByType(results, VerificationResult.VerificationType.BADGE)
            .or(() -> findSuccessByType(results, VerificationResult.VerificationType.DANE))
            .orElseGet(() -> VerificationResult.skipped(
                "No verification performed (no records/registrations found)"));
    }

    /**
     * Finds a successful verification result by type.
     */
    private Optional<VerificationResult> findSuccessByType(List<VerificationResult> results,
                                                            VerificationResult.VerificationType type) {
        return results.stream()
            .filter(r -> r.type() == type && r.isSuccess())
            .findFirst();
    }

    /**
     * Builder for DefaultConnectionVerifier.
     */
    public static class Builder {
        private DaneVerifier daneVerifier;
        private BadgeVerifier badgeVerifier;
        private ScittVerifierAdapter scittVerifier;

        private Builder() {
        }

        /**
         * Sets the DANE verifier.
         *
         * @param daneVerifier the DANE verifier (null to disable DANE)
         * @return this builder
         */
        public Builder daneVerifier(DaneVerifier daneVerifier) {
            this.daneVerifier = daneVerifier;
            return this;
        }

        /**
         * Sets the Badge verifier.
         *
         * @param badgeVerifier the Badge verifier (null to disable Badge)
         * @return this builder
         */
        public Builder badgeVerifier(BadgeVerifier badgeVerifier) {
            this.badgeVerifier = badgeVerifier;
            return this;
        }

        /**
         * Sets the SCITT verifier.
         *
         * @param scittVerifier the SCITT verifier (null to disable SCITT)
         * @return this builder
         */
        public Builder scittVerifier(ScittVerifierAdapter scittVerifier) {
            this.scittVerifier = scittVerifier;
            return this;
        }

        /**
         * Builds the DefaultConnectionVerifier.
         *
         * @return the built verifier
         */
        public DefaultConnectionVerifier build() {
            return new DefaultConnectionVerifier(this);
        }
    }
}
