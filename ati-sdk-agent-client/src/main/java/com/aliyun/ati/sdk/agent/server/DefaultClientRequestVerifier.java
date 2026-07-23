package com.aliyun.ati.sdk.agent.server;

import com.aliyun.ati.sdk.agent.VerificationPolicy;
import com.aliyun.ati.sdk.agent.verification.DaneTlsaVerifier;
import com.aliyun.ati.sdk.agent.verification.TlsaUtils;
import com.aliyun.ati.sdk.crypto.CertificateUtils;
import com.aliyun.ati.sdk.transparency.verification.BadgeVerificationService;
import com.aliyun.ati.sdk.transparency.verification.ClientVerificationResult;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Default implementation of {@link ClientRequestVerifier}.
 *
 * <p>This verifier implements ATI spec section 9 for server-side client verification.
 * Unlike the ANS-style SCITT header approach, ATI uses Badge (transparency log)
 * and DANE (DNSSEC-secured TLSA records) for client verification.</p>
 *
 * <h2>Verification Flow</h2>
 * <ol>
 *   <li>Extract {@code clientAgentHost} from the client Identity Certificate's
 *       URI SAN ({@code ati://v1.client-agent.example.com})</li>
 *   <li>Based on {@link VerificationPolicy}:
 *     <ul>
 *       <li><b>NONE</b>: Skip all client verification (dev/test only)</li>
 *       <li><b>BASIC</b>: No Badge or DANE verification; extract identity from URI SAN</li>
 *       <li><b>ENHANCED</b>: Look up DNS {@code _ati-badge.{clientAgentHost}},
 *           query transparency log, verify seal signature + Merkle proof,
 *           compare SHA256(clientCert) vs identityCertFingerprint</li>
 *       <li><b>ADVANCED</b>: Enhanced + DNS
 *           {@code _ati-identity._tls.{clientAgentHost}} TLSA record,
 *           compare client Identity Cert public key fingerprint vs TLSA record</li>
 *     </ul>
 *   </li>
 * </ol>
 *
 * <h2>Key Design Decisions</h2>
 * <ul>
 *   <li><b>Synchronous:</b> Badge and DANE operations are synchronous for simplicity.
 *       Use a thread pool externally if non-blocking is needed.</li>
 *   <li><b>No HTTP headers:</b> Badge and DANE do not require client-provided HTTP headers;
 *       verification is based solely on the client certificate and DNS records.</li>
 *   <li><b>DANE uses {@code _ati-identity._tls}:</b> For client identity cert verification,
 *       NOT {@code _443._tcp} (which is for server TLS certificates).</li>
 * </ul>
 *
 * @see ClientRequestVerifier
 */
public class DefaultClientRequestVerifier implements ClientRequestVerifier {

    private static final Logger LOGGER = LoggerFactory.getLogger(DefaultClientRequestVerifier.class);

    /**
     * Pattern to extract host from ATI name URI SAN.
     * Matches: ati://v{x.x.x}.{host} or ati://{host}
     * <p>Version is always three-segment (e.g., v1.0.0, v1.1.2).
     * Examples:
     * <ul>
     *   <li>ati://v1.0.0.client-agent.example.com -> client-agent.example.com</li>
     *   <li>ati://v1.1.2.ats-client.asia -> ats-client.asia</li>
     * </ul>
     */
    private static final Pattern ATI_NAME_HOST_PATTERN = Pattern.compile(
        "^(?:ati|ans)://(?:v\\d+(?:\\.\\d+)*\\.)?(.+)$",
        Pattern.CASE_INSENSITIVE
    );

    /**
     * DNS prefix for identity certificate TLSA records.
     * Per ATI spec, client identity certs use _ati-identity._tls, NOT _443._tcp.
     */
    private static final String IDENTITY_TLSA_PREFIX = "_ati-identity._tls.";

    private final BadgeVerificationService badgeVerificationService;
    private final DaneTlsaVerifier daneTlsaVerifier; // nullable, only needed for ADVANCED

    private DefaultClientRequestVerifier(Builder builder) {
        this.badgeVerificationService = builder.badgeVerificationService;
        this.daneTlsaVerifier = builder.daneTlsaVerifier;
    }

    @Override
    public ClientRequestVerificationResult verify(
            X509Certificate clientCert,
            VerificationPolicy policy) {

        Objects.requireNonNull(policy, "policy cannot be null");

        long startNanos = System.nanoTime();

        if (policy == VerificationPolicy.NONE) {
            LOGGER.debug("NONE policy: skipping all client verification");
            return ClientRequestVerificationResult.success(
                null, null, policy, elapsed(startNanos));
        }

        Objects.requireNonNull(clientCert, "clientCert cannot be null");

        try {
            // Step 1: Extract clientAgentHost from URI SAN (type 6)
            Optional<String> atiNameOpt = CertificateUtils.extractAtiName(clientCert);
            if (atiNameOpt.isEmpty()) {
                LOGGER.warn("No ATI URI SAN found in client certificate [subject={}]",
                    clientCert.getSubjectX500Principal().getName());
                return ClientRequestVerificationResult.failure(
                    "No ATI URI SAN found in client certificate",
                    null,
                    policy,
                    elapsed(startNanos)
                );
            }

            String atiName = atiNameOpt.get();
            String agentHost = extractHostFromAtiName(atiName);
            if (agentHost == null || agentHost.isBlank()) {
                LOGGER.warn("Failed to extract host from ATI name: {}", atiName);
                return ClientRequestVerificationResult.failure(
                    "Invalid ATI name format: " + atiName,
                    null,
                    policy,
                    elapsed(startNanos)
                );
            }

            LOGGER.debug("Extracted agentHost='{}' from ATI name '{}'", agentHost, atiName);

            // Step 2: BASIC -> done (no Badge or DANE verification)
            if (policy == VerificationPolicy.BASIC) {
                LOGGER.debug("BASIC policy: skipping Badge/DANE verification for {}", agentHost);
                return ClientRequestVerificationResult.success(
                    null,
                    agentHost,
                    policy,
                    elapsed(startNanos)
                );
            }

            // Step 3: Badge verification (ENHANCED and ADVANCED)
            if (badgeVerificationService == null) {
                LOGGER.error("Badge verification required but badgeVerificationService is not configured");
                return ClientRequestVerificationResult.failure(
                    "Badge verification required but badgeVerificationService is not configured",
                    agentHost,
                    policy,
                    elapsed(startNanos)
                );
            }

            ClientVerificationResult badgeResult = badgeVerificationService.verifyClient(clientCert);
            if (!badgeResult.isSuccess()) {
                String badgeError = buildBadgeErrorMessage(badgeResult);
                LOGGER.warn("Badge verification failed for {}: {}", agentHost, badgeError);
                return ClientRequestVerificationResult.failure(
                    badgeError,
                    agentHost,
                    policy,
                    elapsed(startNanos)
                );
            }

            // Badge passed - use ATI name as agent identity
            // (TransparencyLog does not expose a separate agentId field;
            //  the ATI name from the cert serves as the canonical agent identifier)
            String agentId = atiName;

            // Verify certificate fingerprint matches the transparency log
            String clientFingerprint = CertificateUtils.computeSha256Fingerprint(clientCert);
            String expectedFingerprint = badgeResult.getExpectedIdentityCertFingerprint();
            if (expectedFingerprint != null
                    && !CertificateUtils.fingerprintMatches(clientFingerprint, expectedFingerprint)) {
                LOGGER.debug("Post-verify: Client IDCA vs TL - mismatch");
                LOGGER.warn("Certificate fingerprint mismatch for {}: actual={}, expected={}",
                    agentHost,
                    CertificateUtils.truncateFingerprint(clientFingerprint),
                    CertificateUtils.truncateFingerprint(expectedFingerprint));
                return ClientRequestVerificationResult.failure(
                    List.of(
                        "Certificate fingerprint mismatch",
                        "Actual: " + CertificateUtils.truncateFingerprint(clientFingerprint),
                        "Expected: " + CertificateUtils.truncateFingerprint(expectedFingerprint)
                    ),
                    agentHost,
                    policy,
                    elapsed(startNanos),
                    clientFingerprint,
                    expectedFingerprint,
                    null, null
                );
            }
            LOGGER.debug("Post-verify: Client IDCA vs TL - matched");

            LOGGER.debug("Badge verification succeeded for {} (agentId={})", agentHost, agentId);

            // Step 4: DANE verification (ADVANCED only)
            String daneActual = null;
            String daneExpected = null;
            if (policy == VerificationPolicy.ADVANCED) {
                DaneVerifyResult daneResult = verifyDane(clientCert, agentHost);
                daneActual = daneResult.actualFingerprint;
                daneExpected = daneResult.expectedFingerprint;
                if (!daneResult.errors.isEmpty()) {
                    LOGGER.debug("Post-verify: Client IDCA public key vs TLSA - mismatch");
                    LOGGER.warn("DANE verification failed for {}: {}", agentHost, daneResult.errors);
                    return ClientRequestVerificationResult.failure(
                        daneResult.errors,
                        agentHost,
                        policy,
                        elapsed(startNanos),
                        clientFingerprint,
                        expectedFingerprint,
                        daneActual,
                        daneExpected
                    );
                }
                LOGGER.debug("Post-verify: Client IDCA public key vs TLSA - matched");
                LOGGER.debug("DANE verification succeeded for {}", agentHost);
            }

            // All checks passed
            LOGGER.info("Client verification successful for agentHost={}, agentId={}, policy={}",
                agentHost, agentId, policy);
            return ClientRequestVerificationResult.success(
                agentId,
                agentHost,
                policy,
                elapsed(startNanos),
                clientFingerprint,
                expectedFingerprint,
                daneActual,
                daneExpected
            );

        } catch (Exception e) {
            LOGGER.error("Unexpected error during client verification", e);
            return ClientRequestVerificationResult.failure(
                "Verification error: " + e.getMessage(),
                null,
                policy,
                elapsed(startNanos)
            );
        }
    }

    // ==================== DANE Verification ====================

    /**
     * Result of DANE verification, carrying both errors and fingerprint details.
     */
    private static class DaneVerifyResult {
        final List<String> errors;
        final String actualFingerprint;
        final String expectedFingerprint;

        DaneVerifyResult(List<String> errors, String actualFingerprint, String expectedFingerprint) {
            this.errors = errors;
            this.actualFingerprint = actualFingerprint;
            this.expectedFingerprint = expectedFingerprint;
        }
    }

    /**
     * Performs DANE TLSA verification for the client identity certificate.
     *
     * <p>Queries {@code _ati-identity._tls.{agentHost}} for TLSA records and
     * compares the client certificate's public key fingerprint against them.</p>
     *
     * @param clientCert the client certificate
     * @param agentHost the agent hostname
     * @return DaneVerifyResult with errors and fingerprint details
     */
    private DaneVerifyResult verifyDane(X509Certificate clientCert, String agentHost) {
        List<String> errors = new ArrayList<>();
        String actualFingerprint = null;
        String expectedFingerprint = null;

        if (daneTlsaVerifier == null) {
            errors.add("DANE verification required but daneTlsaVerifier is not configured");
            return new DaneVerifyResult(errors, null, null);
        }

        try {
            // Query _ati-identity._tls.{agentHost} for TLSA expectations
            List<DaneTlsaVerifier.TlsaExpectation> expectations =
                daneTlsaVerifier.getTlsaExpectations(
                    IDENTITY_TLSA_PREFIX + agentHost
                );

            if (expectations.isEmpty()) {
                errors.add("No TLSA record found at _ati-identity._tls." + agentHost);
                return new DaneVerifyResult(errors, null, null);
            }

            // Capture expected fingerprint from first TLSA record as fallback for display
            expectedFingerprint = TlsaUtils.bytesToHex(expectations.get(0).expectedData());
            DaneTlsaVerifier.TlsaExpectation firstExp = expectations.get(0);
            byte[] firstActualData = TlsaUtils.computeCertificateData(
                clientCert, firstExp.selector(), firstExp.matchingType());
            if (firstActualData != null) {
                actualFingerprint = TlsaUtils.bytesToHex(firstActualData);
            }

            // Compare client certificate against each TLSA expectation
            boolean matched = false;
            for (DaneTlsaVerifier.TlsaExpectation expectation : expectations) {
                byte[] certData = TlsaUtils.computeCertificateData(
                    clientCert, expectation.selector(), expectation.matchingType());
                if (certData != null
                        && java.security.MessageDigest.isEqual(certData, expectation.expectedData())) {
                    LOGGER.debug("DANE TLSA match found for {} ({})",
                        agentHost,
                        TlsaUtils.describeMatchType(expectation.selector(), expectation.matchingType()));
                    // Use the matching record's fingerprints for accurate display
                    actualFingerprint = TlsaUtils.bytesToHex(certData);
                    expectedFingerprint = TlsaUtils.bytesToHex(expectation.expectedData());
                    matched = true;
                    break;
                }
            }

            if (!matched) {
                errors.add("Client certificate does not match any TLSA record at _ati-identity._tls." + agentHost);
            }

        } catch (Exception e) {
            LOGGER.warn("DANE TLSA lookup failed for {}: {}", agentHost, e.getMessage());
            errors.add("DANE TLSA lookup failed: " + e.getMessage());
        }

        return new DaneVerifyResult(errors, actualFingerprint, expectedFingerprint);
    }

    // ==================== Helper Methods ====================

    /**
     * Extracts the host portion from an ATI name URI.
     *
     * <p>Examples:</p>
     * <ul>
     *   <li>{@code ati://v1.client-agent.example.com} -> {@code client-agent.example.com}</li>
     *   <li>{@code ati://v1.0.0.client-agent.example.com} -> {@code client-agent.example.com}</li>
     *   <li>{@code ans://v1.client-agent.example.com} -> {@code client-agent.example.com}</li>
     * </ul>
     *
     * @param atiName the ATI name URI
     * @return the host portion, or null if parsing fails
     */
    static String extractHostFromAtiName(String atiName) {
        if (atiName == null) {
            return null;
        }
        Matcher matcher = ATI_NAME_HOST_PATTERN.matcher(atiName);
        if (matcher.matches()) {
            return matcher.group(1);
        }
        return null;
    }

    /**
     * Builds a human-readable error message from a badge verification result.
     */
    private String buildBadgeErrorMessage(ClientVerificationResult badgeResult) {
        StringBuilder msg = new StringBuilder("Badge verification failed: ");
        msg.append(badgeResult.getStatus());
        if (badgeResult.getWarningMessage() != null) {
            msg.append(" - ").append(badgeResult.getWarningMessage());
        }
        return msg.toString();
    }

    /**
     * Calculates elapsed duration since start time.
     */
    private Duration elapsed(long startNanos) {
        return Duration.ofNanos(System.nanoTime() - startNanos);
    }

    /**
     * Creates a new builder.
     *
     * @return a new builder instance
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for DefaultClientRequestVerifier.
     */
    public static class Builder {
        private BadgeVerificationService badgeVerificationService;
        private DaneTlsaVerifier daneTlsaVerifier;

        /**
         * Sets the badge verification service for transparency log verification.
         *
         * <p>Required for {@link VerificationPolicy#ENHANCED} and
         * {@link VerificationPolicy#ADVANCED} policies.</p>
         *
         * @param badgeVerificationService the badge verification service
         * @return this builder
         */
        public Builder badgeVerificationService(BadgeVerificationService badgeVerificationService) {
            this.badgeVerificationService = badgeVerificationService;
            return this;
        }

        /**
         * Sets the DANE TLSA verifier for DNSSEC-based verification.
         *
         * <p>Required for {@link VerificationPolicy#ADVANCED} policy.
         * If not set, ADVANCED policy will fail with an error.</p>
         *
         * @param daneTlsaVerifier the DANE TLSA verifier
         * @return this builder
         */
        public Builder daneTlsaVerifier(DaneTlsaVerifier daneTlsaVerifier) {
            this.daneTlsaVerifier = daneTlsaVerifier;
            return this;
        }

        /**
         * Builds the verifier.
         *
         * <p>No dependencies are strictly required at build time. The verifier
         * will report errors at verification time if required services are missing
         * for the requested policy (e.g., missing badgeVerificationService for
         * ENHANCED policy).</p>
         *
         * @return the configured verifier
         */
        public DefaultClientRequestVerifier build() {
            return new DefaultClientRequestVerifier(this);
        }
    }
}
