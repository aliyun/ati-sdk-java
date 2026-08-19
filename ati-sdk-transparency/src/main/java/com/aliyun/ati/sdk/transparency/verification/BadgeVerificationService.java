package com.aliyun.ati.sdk.transparency.verification;

import com.aliyun.ati.sdk.concurrent.AtiExecutors;
import com.aliyun.ati.sdk.crypto.CertificateUtils;
import com.aliyun.ati.sdk.transparency.TransparencyClient;
import com.aliyun.ati.sdk.transparency.dns.RaBadgeLookupService;
import com.aliyun.ati.sdk.transparency.dns.RaBadgeRecord;
import com.aliyun.ati.sdk.transparency.model.TransparencyLog;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;

/**
 * Service for verifying ATI agents against the transparency log.
 *
 * <p>This service implements the verification flows described in AGENT_TO_AGENT_FLOW.md:</p>
 * <ul>
 *   <li><b>Server verification</b>: Verifies that a server is a registered ATI agent
 *       by looking up its _ati-badge DNS record and checking the transparency log.</li>
 *   <li><b>Client verification</b>: Verifies that an mTLS client certificate belongs
 *       to a registered ATI agent.</li>
 * </ul>
 *
 * <p>Example usage:</p>
 * <pre>{@code
 * BadgeVerificationService verifier = BadgeVerificationService.builder()
 *     .transparencyClient(TransparencyClient.createDefault())
 *     .build();
 *
 * // Verify a server before connecting
 * ServerVerificationResult result = verifier.verifyServer("agent.example.com");
 * if (result.isSuccess()) {
 *     // Proceed with connection, verify TLS cert fingerprint matches
 *     String expectedFingerprint = result.getExpectedServerCertFingerprint();
 * }
 *
 * // Verify a client certificate during mTLS handshake
 * ClientVerificationResult clientResult = verifier.verifyClient(clientCert);
 * if (clientResult.isSuccess()) {
 *     // Client is verified
 * }
 * }</pre>
 */
public final class BadgeVerificationService implements ServerVerifier {

    private static final Logger LOG = LoggerFactory.getLogger(BadgeVerificationService.class);

    /**
     * Valid registration statuses that allow verification to proceed.
     */
    private static final Set<String> ACTIVE_STATUSES = Set.of("ACTIVE", "WARNING");

    /**
     * Registration status indicating deprecated but still acceptable.
     */
    private static final String DEPRECATED_STATUS = "DEPRECATED";

    /**
     * Invalid registration statuses that cause verification to fail.
     */
    private static final Set<String> INVALID_STATUSES = Set.of("REVOKED", "EXPIRED");

    /**
     * Pattern to extract version from ATI/ANS name.
     * Format: ati://v{major}.{minor}.{patch}.{host} or ans://v{major}.{minor}.{patch}.{host}
     * Example: ati://v1.1.2.ats-client.asia -> 1.1.2
     */
    private static final Pattern ATI_VERSION_PATTERN = Pattern.compile(
        "^(?:ati|ans)://v?(\\d+\\.\\d+\\.\\d+)\\.",
        Pattern.CASE_INSENSITIVE
    );

    private final TransparencyClient transparencyClient;
    private final RaBadgeLookupService raBadgeLookupService;
    private final Executor executor;

    private BadgeVerificationService(Builder builder) {
        this.transparencyClient = Objects.requireNonNull(
            builder.transparencyClient, "transparencyClient is required");
        this.raBadgeLookupService = builder.raBadgeLookupService != null
            ? builder.raBadgeLookupService
            : new RaBadgeLookupService();
        this.executor = builder.executor != null
            ? builder.executor
            : AtiExecutors.sharedIoExecutor();
    }

    /**
     * Verifies a server against the transparency log.
     *
     * <p>This method:</p>
     * <ol>
     *   <li>Looks up ALL _ati-badge TXT records for the hostname (supports version rotation)</li>
     *   <li>Fetches registrations from the transparency log in parallel</li>
     *   <li>Checks registration statuses</li>
     *   <li>Returns ALL expected server certificate fingerprints for comparison</li>
     * </ol>
     *
     * @param hostname the server hostname to verify
     * @return the verification result with all valid fingerprints
     */
    public ServerVerificationResult verifyServer(String hostname) {
        Objects.requireNonNull(hostname, "hostname is required");
        LOG.debug("Verifying server: {}", hostname);

        try {
            // Step 1: Look up ALL badge DNS records (tries _ati-badge first, falls back to _ati-badge)
            List<RaBadgeRecord> badges = raBadgeLookupService.lookupBadges(hostname);
            if (badges.isEmpty()) {
                LOG.debug("No badge record found for {}", hostname);
                return ServerVerificationResult.builder()
                    .status(VerificationStatus.NOT_ATI_AGENT)
                    .build();
            }

            LOG.debug("Found {} badge records for {}", badges.size(), hostname);

            // Spec 7.1: extract the path from u= and fetch via TransparencyClient.baseUrl.
            // Do not drop a record because the Badge TXT u= host is outside Trusted TL Domain.
            List<RaBadgeRecord> badgesWithPaths = badges.stream()
                .filter(badge -> badge.tlPath() != null && !badge.tlPath().isBlank())
                .collect(Collectors.toList());

            if (badgesWithPaths.isEmpty()) {
                LOG.warn("No badge records with valid paths for {}", hostname);
                return ServerVerificationResult.builder()
                    .status(VerificationStatus.LOOKUP_FAILED)
                    .warningMessage("Invalid badge records: missing paths")
                    .build();
            }

            // Fetch via TransparencyClient.baseUrl + path (Spec 7.1)
            LOG.debug("Fetching {} registrations in parallel for server verification", badgesWithPaths.size());
            List<FetchResult> fetchResults = fetchRegistrationsInParallel(badgesWithPaths);

            return evaluateServerRegistrations(fetchResults);

        } catch (Exception e) {
            LOG.error("Failed to verify server {}: {}", hostname, e.getMessage());
            return ServerVerificationResult.builder()
                .status(VerificationStatus.LOOKUP_FAILED)
                .warningMessage("Lookup failed: " + e.getMessage())
                .build();
        }
    }

    /**
     * Verifies a client certificate against the transparency log.
     *
     * <p>This method:</p>
     * <ol>
     *   <li>Extracts the {@code clientAgentHost} from the client certificate's URI SAN
     *       (e.g., {@code ati://v1.client-agent.example.com} -> {@code client-agent.example.com})</li>
     *   <li>Extracts the CN for agent.host matching (Section 4.4)</li>
     *   <li>Looks up the _ati-badge TXT record for the agentHost</li>
     *   <li>Fetches the registration(s) from the transparency log</li>
     *   <li>Matches the certificate fingerprint and ANS name</li>
     * </ol>
     *
     * @param clientCert the client certificate to verify
     * @return the verification result
     */
    public ClientVerificationResult verifyClient(X509Certificate clientCert) {
        Objects.requireNonNull(clientCert, "clientCert is required");
        LOG.debug("Verifying client certificate: {}", clientCert.getSubjectX500Principal());

        try {
            // Step 1: Extract agentHost from URI SAN (type 6) per spec §9.2
            // The server must use the ATI name URI SAN, not DNS SAN or CN, for badge lookup
            Optional<String> certAtiName = CertificateUtils.extractAtiName(clientCert);
            if (certAtiName.isEmpty()) {
                LOG.warn("Client certificate has no ATI URI SAN");
                return ClientVerificationResult.builder()
                    .status(VerificationStatus.LOOKUP_FAILED)
                    .warningMessage("Certificate has no ATI URI SAN")
                    .build();
            }

            String agentHost = CertificateUtils.extractHostFromAtiName(certAtiName.get());
            if (agentHost == null || agentHost.isBlank()) {
                LOG.warn("Failed to extract host from ATI name: {}", certAtiName.get());
                return ClientVerificationResult.builder()
                    .status(VerificationStatus.LOOKUP_FAILED)
                    .warningMessage("Invalid ATI name format: " + certAtiName.get())
                    .build();
            }

            // Step 3: Extract version from ANS name for efficient badge filtering
            String certVersion = certAtiName.map(this::extractVersionFromAtiName).orElse(null);

            // Step 4: Compute client certificate fingerprint
            String clientFingerprint = CertificateUtils.computeSha256Fingerprint(clientCert);

            // Step 5: Look up badge DNS records using agentHost from URI SAN
            List<RaBadgeRecord> badges = raBadgeLookupService.lookupBadges(agentHost);
            if (badges.isEmpty()) {
                LOG.debug("No badge record found for {}", agentHost);
                return ClientVerificationResult.builder()
                    .status(VerificationStatus.NOT_ATI_AGENT)
                    .build();
            }

            // Spec 7.1: path from u=, HTTP via TransparencyClient.baseUrl — not Badge TXT u= host allowlisting.
            List<RaBadgeRecord> filteredBadges = filterBadgesByVersion(badges, certVersion);
            if (filteredBadges.isEmpty()) {
                LOG.debug("No badges match version {}, checking all {} badges", certVersion, badges.size());
                filteredBadges = badges;
            } else {
                LOG.debug("Filtered {} badges to {} matching version {}",
                    badges.size(), filteredBadges.size(), certVersion);
            }

            // Step 8: Check each registration for matching fingerprint, agentHost, and ANS name
            return findMatchingClientRegistration(filteredBadges, clientFingerprint, certAtiName.orElse(null), agentHost);

        } catch (Exception e) {
            LOG.error("Failed to verify client: {}", e.getMessage());
            return ClientVerificationResult.builder()
                .status(VerificationStatus.LOOKUP_FAILED)
                .warningMessage("Lookup failed: " + e.getMessage())
                .build();
        }
    }

    /**
     * Evaluates multiple server registrations and collects all valid fingerprints.
     *
     * <p>This method processes all fetch results and returns a combined result with
     * all valid fingerprints from ACTIVE or DEPRECATED registrations.</p>
     */
    private ServerVerificationResult evaluateServerRegistrations(List<FetchResult> fetchResults) {
        List<String> activeFingerprints = new ArrayList<>();
        List<String> deprecatedFingerprints = new ArrayList<>();
        TransparencyLog firstActiveRegistration = null;
        TransparencyLog firstDeprecatedRegistration = null;
        TransparencyLog firstInvalidRegistration = null;
        String agentHost = null;
        boolean hasWarning = false;
        String lastInvalidStatus = null;
        String lastErrorMessage = null;
        boolean anySealVerified = false;
        boolean anyMerkleVerified = false;
        boolean anyFingerprintExtracted = false;

        for (FetchResult fetchResult : fetchResults) {
            if (!fetchResult.isSuccess()) {
                // Track the last error message for diagnostics
                if (fetchResult.error() != null) {
                    lastErrorMessage = fetchResult.error().getMessage();
                }
                continue;
            }

            if (fetchResult.sealVerified()) anySealVerified = true;
            if (fetchResult.merkleVerified()) anyMerkleVerified = true;

            TransparencyLog registration = fetchResult.registration();
            String status = registration.getStatus();
            String fingerprint = registration.getServerCertFingerprint();

            // Sub-step 3: Extract serverCertFingerprint
            if (fingerprint == null || fingerprint.isBlank()) {
                LOG.info("预认证 Badge 子步骤3/3: 获取serverCertFingerprint - 失败 (注册记录中无指纹)");
                LOG.debug("Skipping registration with no fingerprint");
                continue;
            }

            LOG.info("预认证 Badge 子步骤3/3: 获取serverCertFingerprint - 成功");
            anyFingerprintExtracted = true;

            if (ACTIVE_STATUSES.contains(status)) {
                activeFingerprints.add(fingerprint);
                if (firstActiveRegistration == null) {
                    firstActiveRegistration = registration;
                    agentHost = registration.getAgentHost();
                }
                if ("WARNING".equals(status)) {
                    hasWarning = true;
                }
                LOG.debug("Found ACTIVE registration with fingerprint: {}...",
                    fingerprint.length() > 20 ? fingerprint.substring(0, 20) : fingerprint);
            } else if (DEPRECATED_STATUS.equals(status)) {
                                deprecatedFingerprints.add(fingerprint);
                if (firstDeprecatedRegistration == null) {
                    firstDeprecatedRegistration = registration;
                    if (agentHost == null) {
                        agentHost = registration.getAgentHost();
                    }
                }
                LOG.debug("Found DEPRECATED registration with fingerprint: {}...",
                    fingerprint.length() > 20 ? fingerprint.substring(0, 20) : fingerprint);
            } else {
                // INVALID_STATUSES (REVOKED, EXPIRED) or unknown status
                if (firstInvalidRegistration == null) {
                    firstInvalidRegistration = registration;
                }
                lastInvalidStatus = status;
                LOG.debug("Skipping registration with invalid/unknown status: {}", status);
            }
        }

        // Return result with all valid fingerprints
        if (!activeFingerprints.isEmpty()) {
            // Combine active and deprecated fingerprints (active takes priority)
            List<String> allFingerprints = new ArrayList<>(activeFingerprints);
            allFingerprints.addAll(deprecatedFingerprints);

            LOG.debug("Server verification succeeded with {} active and {} deprecated fingerprints",
                activeFingerprints.size(), deprecatedFingerprints.size());

            ServerVerificationResult.Builder builder = ServerVerificationResult.builder()
                .status(VerificationStatus.VERIFIED)
                .registration(firstActiveRegistration)
                .expectedServerCertFingerprints(allFingerprints)
                .expectedAgentHost(agentHost)
                .sealVerified(anySealVerified)
                .merkleVerified(anyMerkleVerified)
                .fingerprintExtracted(anyFingerprintExtracted);

            if (hasWarning) {
                builder.warningMessage("One or more registrations have WARNING status");
            }
            return builder.build();
        }

        if (!deprecatedFingerprints.isEmpty()) {
            LOG.debug("Server verification succeeded with {} deprecated fingerprints",
                deprecatedFingerprints.size());

            return ServerVerificationResult.builder()
                .status(VerificationStatus.DEPRECATED_OK)
                .registration(firstDeprecatedRegistration)
                .expectedServerCertFingerprints(deprecatedFingerprints)
                .expectedAgentHost(agentHost)
                .warningMessage("All registrations are deprecated")
                .sealVerified(anySealVerified)
                .merkleVerified(anyMerkleVerified)
                .fingerprintExtracted(anyFingerprintExtracted)
                .build();
        }

        // All registrations were invalid/unknown status or no valid fingerprints found
        if (lastInvalidStatus != null && firstInvalidRegistration != null) {
            LOG.warn("All server registrations have invalid status: {}", lastInvalidStatus);
            String warningMessage = INVALID_STATUSES.contains(lastInvalidStatus)
                ? "Registration status: " + lastInvalidStatus
                : "Unknown registration status: " + lastInvalidStatus;
            return ServerVerificationResult.builder()
                .status(VerificationStatus.REGISTRATION_INVALID)
                .registration(firstInvalidRegistration)
                .warningMessage(warningMessage)
                .sealVerified(anySealVerified)
                .merkleVerified(anyMerkleVerified)
                .fingerprintExtracted(anyFingerprintExtracted)
                .failureStep(anyFingerprintExtracted ? null : "fingerprint")
                .build();
        }

        // All fetches failed - include the last error message for diagnostics
        String warningMessage = "Failed to fetch any valid registrations";
        if (lastErrorMessage != null) {
            warningMessage += ": " + lastErrorMessage;
        }

        // Determine failure step
        String failureStep = "seal";
        if (anySealVerified) {
            failureStep = "merkle";
            if (anyMerkleVerified) {
                failureStep = "fingerprint";
            }
        }

        return ServerVerificationResult.builder()
            .status(VerificationStatus.LOOKUP_FAILED)
            .warningMessage(warningMessage)
            .sealVerified(anySealVerified)
            .merkleVerified(anyMerkleVerified)
            .fingerprintExtracted(anyFingerprintExtracted)
            .failureStep(failureStep)
            .build();
    }

    /**
     * Result of fetching a registration from the transparency log.
     */
    private record FetchResult(
            RaBadgeRecord badge,
            TransparencyLog registration,
            Exception error,
            boolean sealVerified,
            boolean merkleVerified
    ) {
        static FetchResult success(RaBadgeRecord badge, TransparencyLog registration,
                                   boolean sealVerified, boolean merkleVerified) {
            return new FetchResult(badge, registration, null, sealVerified, merkleVerified);
        }

        static FetchResult failure(RaBadgeRecord badge, Exception error) {
            return new FetchResult(badge, null, error, false, false);
        }

        boolean isSuccess() {
            return registration != null;
        }
    }

    /**
     * Finds a matching client registration from the given badges.
     *
     * <p>This method fetches all registrations in parallel for performance,
     * then processes them in order to find the best match.</p>
     */
    private ClientVerificationResult findMatchingClientRegistration(
            List<RaBadgeRecord> badges,
            String clientFingerprint,
            String certAtiName,
            String agentHost) {

        // Filter badges with valid paths (spec 7.1: use full path)
        List<RaBadgeRecord> validBadges = badges.stream()
            .filter(badge -> badge.tlPath() != null && !badge.tlPath().isBlank())
            .collect(Collectors.toList());

        if (validBadges.isEmpty()) {
            return ClientVerificationResult.builder()
                .status(VerificationStatus.LOOKUP_FAILED)
                .warningMessage("No valid badge records with paths")
                .build();
        }

        // Fetch all registrations in parallel
        LOG.debug("Fetching {} registrations in parallel", validBadges.size());
        List<FetchResult> fetchResults = fetchRegistrationsInParallel(validBadges);

        // Process results in order to find the best match
        return processFetchResults(fetchResults, clientFingerprint, certAtiName, agentHost);
    }

    /**
     * Fetches registrations for all badges in parallel, with seal + Merkle verification.
     *
     * <p>Per spec 7.1, uses the full path from the badge URL concatenated with the
     * configured TL base-url, rather than reconstructing from agentId. This ensures
     * that even if DNS is compromised, the SDK only talks to the configured TL.</p>
     *
     * <p>Per spec 8.2, after fetching, verifies the seal signature (SHA-256withECDSA + RFC 8785 JCS)
     * and Merkle inclusion proof (RFC 9162) if present in the response.</p>
     */
    private List<FetchResult> fetchRegistrationsInParallel(List<RaBadgeRecord> badges) {
        // Create futures for all badge lookups
        List<CompletableFuture<FetchResult>> futures = badges.stream()
            .map(badge -> CompletableFuture.supplyAsync(() -> {
                try {
                    // Spec 7.1: use full path from badge URL, not reconstructed from agentId
                    TransparencyLog registration = transparencyClient.getTransparencyLogByPath(badge.tlPath());

                    // Spec 8.2: verify seal signature and Merkle proof if present
                    SealVerifier.VerificationResult sealResult = SealVerifier.verify(registration);

                    // Sub-step 1: Seal signature verification
                    boolean sealOk = sealResult.sealValid() == null || sealResult.sealValid();
                    LOG.info("预认证 Badge 子步骤1/3: Seal签名验证 - {}", sealOk ? "成功" : "失败");
                    if (!sealOk) {
                        LOG.warn("Seal verification failed for path {}: {}",
                            badge.tlPath(), sealResult.failureReason());
                        return FetchResult.failure(badge,
                            new SecurityException("Seal signature verification failed: "
                                + sealResult.failureReason()));
                    }

                    // Sub-step 2: Merkle proof verification
                    boolean merkleOk = sealResult.merkleValid() == null || sealResult.merkleValid();
                    LOG.info("预认证 Badge 子步骤2/3: Merkle Proof验证 - {}", merkleOk ? "成功" : "失败");
                    if (!merkleOk) {
                        LOG.warn("Merkle proof verification failed for path {}: {}",
                            badge.tlPath(), sealResult.failureReason());
                        return FetchResult.failure(badge,
                            new SecurityException("Merkle proof verification failed: "
                                + sealResult.failureReason()));
                    }

                    return FetchResult.success(badge, registration, sealOk, merkleOk);
                } catch (Exception e) {
                    LOG.debug("Failed to fetch registration for path {}: {}", badge.tlPath(), e.getMessage());
                    return FetchResult.failure(badge, e);
                }
            }, executor))
            .toList();

        // Wait for all futures to complete and collect results
        CompletableFuture.allOf(futures.toArray(new CompletableFuture[0])).join();

        return futures.stream()
            .map(CompletableFuture::join)
            .collect(Collectors.toList());
    }

    /**
     * Processes fetch results to find the best matching registration.
     */
    private ClientVerificationResult processFetchResults(
            List<FetchResult> fetchResults,
            String clientFingerprint,
            String certAtiName,
            String agentHost) {

        TransparencyLog activeMatch = null;
        TransparencyLog deprecatedMatch = null;
        TransparencyLog invalidMatch = null;
        String invalidStatus = null;
        TransparencyLog lastRegistration = null;
        String lastMismatchReason = null;

        for (FetchResult fetchResult : fetchResults) {
            if (!fetchResult.isSuccess()) {
                continue;
            }

            TransparencyLog registration = fetchResult.registration();
            lastRegistration = registration;

            String expectedFingerprint = registration.getIdentityCertFingerprint();
            String expectedAtiName = registration.getAtiName();
            String expectedAgentHost = registration.getAgentHost();
            String status = registration.getStatus();
            String agentId = fetchResult.badge().agentId();

            // Check fingerprint match (required per Section 4.4)
            boolean fingerprintMatch = CertificateUtils.fingerprintMatches(
                clientFingerprint, expectedFingerprint);

            if (!fingerprintMatch) {
                LOG.debug("Fingerprint mismatch for agent {}: expected={}, actual={}",
                    agentId, expectedFingerprint, clientFingerprint);
                lastMismatchReason = "fingerprint";
                continue;
            }

            // Check agentHost from URI SAN matches TL agentHost (required per Section 4.4)
            if (agentHost != null && expectedAgentHost != null
                    && !agentHost.equalsIgnoreCase(expectedAgentHost)) {
                LOG.debug("Hostname mismatch for agent {}: expected={}, actual={}",
                    agentId, expectedAgentHost, agentHost);
                lastMismatchReason = "hostname";
                continue;
            }

            // Check ANS name match (required per Section 4.4)
            if (certAtiName != null && expectedAtiName != null
                    && !certAtiName.equals(expectedAtiName)) {
                LOG.debug("ANS name mismatch for agent {}: expected={}, actual={}",
                    agentId, expectedAtiName, certAtiName);
                lastMismatchReason = "ansname";
                continue;
            }

            // All three checks passed - check status
            if (ACTIVE_STATUSES.contains(status)) {
                activeMatch = registration;
                break; // Active match is best, stop searching
            } else if (DEPRECATED_STATUS.equals(status) && deprecatedMatch == null) {
                deprecatedMatch = registration;
                // Continue searching for an active match
            } else if (INVALID_STATUSES.contains(status) && invalidMatch == null) {
                // Registration matches but has invalid status (EXPIRED, REVOKED)
                invalidMatch = registration;
                invalidStatus = status;
                LOG.debug("Found matching registration with {} status for agent {}", status, agentId);
            }
        }

        // Return the best match found
        if (activeMatch != null) {
            LOG.debug("Client verification succeeded with ACTIVE registration");
            return ClientVerificationResult.builder()
                .status(VerificationStatus.VERIFIED)
                .registration(activeMatch)
                .expectedIdentityCertFingerprint(activeMatch.getIdentityCertFingerprint())
                .expectedAtiName(activeMatch.getAtiName())
                .expectedAgentHost(activeMatch.getAgentHost())
                .build();
        }

        if (deprecatedMatch != null) {
            LOG.debug("Client verification succeeded with DEPRECATED registration");
            return ClientVerificationResult.builder()
                .status(VerificationStatus.DEPRECATED_OK)
                .registration(deprecatedMatch)
                .expectedIdentityCertFingerprint(deprecatedMatch.getIdentityCertFingerprint())
                .expectedAtiName(deprecatedMatch.getAtiName())
                .expectedAgentHost(deprecatedMatch.getAgentHost())
                .warningMessage("Registration is deprecated")
                .build();
        }

        // Registration matched but has invalid status (EXPIRED, REVOKED)
        if (invalidMatch != null) {
            LOG.warn("Client verification failed: registration status is {}", invalidStatus);
            return ClientVerificationResult.builder()
                .status(VerificationStatus.REGISTRATION_INVALID)
                .registration(invalidMatch)
                .expectedIdentityCertFingerprint(invalidMatch.getIdentityCertFingerprint())
                .expectedAtiName(invalidMatch.getAtiName())
                .expectedAgentHost(invalidMatch.getAgentHost())
                .warningMessage("Registration status: " + invalidStatus)
                .build();
        }

        // No match found - return appropriate mismatch status
        if (lastRegistration != null) {
            VerificationStatus mismatchStatus;
            String message;

            if ("hostname".equals(lastMismatchReason)) {
                mismatchStatus = VerificationStatus.HOSTNAME_MISMATCH;
                message = "Certificate CN does not match agent.host";
            } else if ("ansname".equals(lastMismatchReason)) {
                mismatchStatus = VerificationStatus.ATI_NAME_MISMATCH;
                message = "Certificate URI SAN does not match atiName";
            } else {
                mismatchStatus = VerificationStatus.FINGERPRINT_MISMATCH;
                message = "Certificate fingerprint does not match registration";
            }

            LOG.warn("Client verification failed: {}", message);
            return ClientVerificationResult.builder()
                .status(mismatchStatus)
                .registration(lastRegistration)
                .expectedIdentityCertFingerprint(lastRegistration.getIdentityCertFingerprint())
                .expectedAtiName(lastRegistration.getAtiName())
                .expectedAgentHost(lastRegistration.getAgentHost())
                .warningMessage(message)
                .build();
        }

        return ClientVerificationResult.builder()
            .status(VerificationStatus.LOOKUP_FAILED)
            .warningMessage("Failed to fetch any registrations")
            .build();
    }

    /**
     * Extracts the version from an ANS name.
     *
     * @param atiName the ANS name (e.g., "ans://v1.0.0.agent.example.com")
     * @return the version (e.g., "1.0.0"), or null if not found
     */
    private String extractVersionFromAtiName(String atiName) {
        if (atiName == null) {
            return null;
        }
        Matcher matcher = ATI_VERSION_PATTERN.matcher(atiName);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }

    /**
     * Filters badges to only those matching the specified version.
     *
     * <p>This optimization reduces transparency log API calls during version rotation
     * by only fetching registrations for badges that match the certificate version.</p>
     *
     * @param badges the list of badges to filter
     * @param version the version to match (may be null)
     * @return filtered list, or empty if no matches (caller should fall back to all badges)
     */
    private List<RaBadgeRecord> filterBadgesByVersion(List<RaBadgeRecord> badges, String version) {
        if (version == null || badges == null) {
            return List.of();
        }
        return badges.stream()
            .filter(badge -> badge.matchesAgentVersion(version))
            .collect(Collectors.toList());
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
     * Creates a service with the given transparency client.
     *
     * @param transparencyClient the transparency client to use
     * @return a new service instance
     */
    public static BadgeVerificationService create(TransparencyClient transparencyClient) {
        return builder()
            .transparencyClient(transparencyClient)
            .build();
    }

    /**
     * Builder for BadgeVerificationService.
     */
    public static final class Builder {
        private TransparencyClient transparencyClient;
        private RaBadgeLookupService raBadgeLookupService;
        private Executor executor;

        private Builder() {
        }

        /**
         * Sets the transparency client to use for fetching registrations.
         *
         * @param transparencyClient the transparency client
         * @return this builder
         */
        public Builder transparencyClient(TransparencyClient transparencyClient) {
            this.transparencyClient = transparencyClient;
            return this;
        }

        /**
         * Sets a custom badge lookup service.
         *
         * <p>This is primarily useful for testing.</p>
         *
         * @param raBadgeLookupService the lookup service
         * @return this builder
         */
        public Builder raBadgeLookupService(RaBadgeLookupService raBadgeLookupService) {
            this.raBadgeLookupService = raBadgeLookupService;
            return this;
        }

        /**
         * Sets a custom executor for parallel registration lookups.
         *
         * <p>If not specified, a shared bounded thread pool is used.</p>
         *
         * @param executor the executor for async operations
         * @return this builder
         */
        public Builder executor(Executor executor) {
            this.executor = executor;
            return this;
        }

        /**
         * Builds the service.
         *
         * @return the configured service
         */
        public BadgeVerificationService build() {
            return new BadgeVerificationService(this);
        }
    }
}