package com.aliyun.ati.sdk.transparency.verification;

import com.aliyun.ati.sdk.crypto.CertificateUtils;
import com.aliyun.ati.sdk.transparency.TransparencyClient;
import com.aliyun.ati.sdk.transparency.dns.RaBadgeLookupService;
import com.aliyun.ati.sdk.transparency.dns.RaBadgeRecord;
import com.aliyun.ati.sdk.transparency.model.TransparencyLog;
import com.aliyun.ati.sdk.transparency.model.TransparencyLogAtiV1;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.MockitoAnnotations;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

/**
 * Client Verification during Identity Certificate Renewal.
 *
 * <p>A Server Agent performing Client Verification accepts a caller's Identity
 * Certificate when it matches the Badge Entry's current Identity Cert Fingerprint
 * or, during Certificate Renewal, its Previous Identity Cert Fingerprint (same-role
 * OR). Hostname and ATI Name checks still apply after a fingerprint hit. Previous
 * server fingerprints never satisfy identity matching.</p>
 *
 * <p>Tests the {@link BadgeVerificationService#verifyClient(X509Certificate)} seam.</p>
 */
class BadgeClientCertificateRenewalTest {

    private static final String TEST_HOSTNAME = "agent.example.com";
    private static final String TEST_AGENT_ID = "6bf2b7a9-1383-4e33-a945-845f34af7526";
    private static final String TEST_TL_PATH = "/tl/agents/" + TEST_AGENT_ID;
    private static final String TEST_ANS_NAME = "ati://v1.0.0.agent.example.com";

    /** Fingerprint the presented Identity Certificate computes to. */
    private static final String CLIENT_FP = "SHA256:presentedidentitycertfingerprint0001";
    private static final String CURRENT_IDENTITY_FP = "SHA-256:currentidentitycertfingerprint01";
    private static final String PREVIOUS_IDENTITY_FP = "SHA-256:previousidentitycertfingerprint01";
    private static final String CURRENT_SERVER_FP = "SHA-256:currentservercertfingerprint0001";

    @Mock
    private TransparencyClient transparencyClient;

    @Mock
    private RaBadgeLookupService raBadgeLookupService;

    @Mock
    private X509Certificate mockCertificate;

    private BadgeVerificationService verificationService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        verificationService = BadgeVerificationService.builder()
            .transparencyClient(transparencyClient)
            .raBadgeLookupService(raBadgeLookupService)
            .build();
    }

    // ==================== Previous-only match ====================

    @Test
    @DisplayName("ACTIVE Entry: Identity Certificate matching Previous Identity Cert Fingerprint only is VERIFIED")
    void previousOnlyIdentityMatchIsVerified() {
        try (MockedStatic<CertificateUtils> certUtils = mockStatic(CertificateUtils.class)) {
            stubClientCert(certUtils, CLIENT_FP);
            stubIdentityMatch(certUtils, CLIENT_FP, CURRENT_IDENTITY_FP, false);
            stubIdentityMatch(certUtils, CLIENT_FP, PREVIOUS_IDENTITY_FP, true);
            stubSingleBadge();
            when(transparencyClient.getTransparencyLogByPath(TEST_TL_PATH))
                .thenReturn(registration("ACTIVE", CURRENT_IDENTITY_FP, PREVIOUS_IDENTITY_FP));

            ClientVerificationResult result = verificationService.verifyClient(mockCertificate);

            assertThat(result.getStatus()).isEqualTo(VerificationStatus.VERIFIED);
            assertThat(result.getExpectedAgentHost()).isEqualTo(TEST_HOSTNAME);
            assertThat(result.getExpectedAtiName()).isEqualTo(TEST_ANS_NAME);
        }
    }

    @Test
    @DisplayName("DEPRECATED Entry: previous identity match still yields DEPRECATED_OK")
    void deprecatedEntryPreviousIdentityMatchIsDeprecatedOk() {
        try (MockedStatic<CertificateUtils> certUtils = mockStatic(CertificateUtils.class)) {
            stubClientCert(certUtils, CLIENT_FP);
            stubIdentityMatch(certUtils, CLIENT_FP, CURRENT_IDENTITY_FP, false);
            stubIdentityMatch(certUtils, CLIENT_FP, PREVIOUS_IDENTITY_FP, true);
            stubSingleBadge();
            when(transparencyClient.getTransparencyLogByPath(TEST_TL_PATH))
                .thenReturn(registration("DEPRECATED", CURRENT_IDENTITY_FP, PREVIOUS_IDENTITY_FP));

            ClientVerificationResult result = verificationService.verifyClient(mockCertificate);

            assertThat(result.getStatus()).isEqualTo(VerificationStatus.DEPRECATED_OK);
        }
    }

    @Test
    @DisplayName("REVOKED Entry: previous identity match still yields REGISTRATION_INVALID")
    void revokedEntryPreviousIdentityMatchIsRegistrationInvalid() {
        try (MockedStatic<CertificateUtils> certUtils = mockStatic(CertificateUtils.class)) {
            stubClientCert(certUtils, CLIENT_FP);
            stubIdentityMatch(certUtils, CLIENT_FP, CURRENT_IDENTITY_FP, false);
            stubIdentityMatch(certUtils, CLIENT_FP, PREVIOUS_IDENTITY_FP, true);
            stubSingleBadge();
            when(transparencyClient.getTransparencyLogByPath(TEST_TL_PATH))
                .thenReturn(registration("REVOKED", CURRENT_IDENTITY_FP, PREVIOUS_IDENTITY_FP));

            ClientVerificationResult result = verificationService.verifyClient(mockCertificate);

            assertThat(result.getStatus()).isEqualTo(VerificationStatus.REGISTRATION_INVALID);
        }
    }

    @Test
    @DisplayName("EXPIRED Entry: previous identity match still yields REGISTRATION_INVALID")
    void expiredEntryPreviousIdentityMatchIsRegistrationInvalid() {
        try (MockedStatic<CertificateUtils> certUtils = mockStatic(CertificateUtils.class)) {
            stubClientCert(certUtils, CLIENT_FP);
            stubIdentityMatch(certUtils, CLIENT_FP, CURRENT_IDENTITY_FP, false);
            stubIdentityMatch(certUtils, CLIENT_FP, PREVIOUS_IDENTITY_FP, true);
            stubSingleBadge();
            when(transparencyClient.getTransparencyLogByPath(TEST_TL_PATH))
                .thenReturn(registration("EXPIRED", CURRENT_IDENTITY_FP, PREVIOUS_IDENTITY_FP));

            ClientVerificationResult result = verificationService.verifyClient(mockCertificate);

            assertThat(result.getStatus()).isEqualTo(VerificationStatus.REGISTRATION_INVALID);
        }
    }

    // ==================== Hostname / ATI Name still enforced after a previous hit ====================

    @Test
    @DisplayName("Previous identity hit but Identity Hostname mismatch is still HOSTNAME_MISMATCH")
    void previousIdentityMatchButHostnameMismatchIsHostnameMismatch() {
        String certAtiName = "ati://v1.0.0.different-agent.example.com";
        String certHost = "different-agent.example.com";
        try (MockedStatic<CertificateUtils> certUtils = mockStatic(CertificateUtils.class)) {
            certUtils.when(() -> CertificateUtils.extractAtiName(mockCertificate))
                .thenReturn(Optional.of(certAtiName));
            certUtils.when(() -> CertificateUtils.extractHostFromAtiName(certAtiName))
                .thenReturn(certHost);
            certUtils.when(() -> CertificateUtils.computeSha256Fingerprint(mockCertificate))
                .thenReturn(CLIENT_FP);
            // Fingerprint hits Previous Identity Cert Fingerprint ...
            stubIdentityMatch(certUtils, CLIENT_FP, CURRENT_IDENTITY_FP, false);
            stubIdentityMatch(certUtils, CLIENT_FP, PREVIOUS_IDENTITY_FP, true);
            // ... but the Badge Entry resolves to a different Identity Hostname.
            RaBadgeRecord badge = RaBadgeRecord.parse(
                "v=ati-badge1; av=1.0.0; u=https://ati-tl.cnnic.cn:8180/tl/agents/" + TEST_AGENT_ID);
            when(raBadgeLookupService.lookupBadges(certHost)).thenReturn(List.of(badge));
            when(transparencyClient.getTransparencyLogByPath(TEST_TL_PATH))
                .thenReturn(registration("ACTIVE", CURRENT_IDENTITY_FP, PREVIOUS_IDENTITY_FP));

            ClientVerificationResult result = verificationService.verifyClient(mockCertificate);

            assertThat(result.getStatus()).isEqualTo(VerificationStatus.HOSTNAME_MISMATCH);
        }
    }

    @Test
    @DisplayName("Previous identity hit but ATI Name mismatch is still ATI_NAME_MISMATCH")
    void previousIdentityMatchButAtiNameMismatchIsAtiNameMismatch() {
        String certAtiName = "ati://v2.0.0.agent.example.com";
        try (MockedStatic<CertificateUtils> certUtils = mockStatic(CertificateUtils.class)) {
            certUtils.when(() -> CertificateUtils.extractAtiName(mockCertificate))
                .thenReturn(Optional.of(certAtiName));
            certUtils.when(() -> CertificateUtils.extractHostFromAtiName(certAtiName))
                .thenReturn(TEST_HOSTNAME);
            certUtils.when(() -> CertificateUtils.computeSha256Fingerprint(mockCertificate))
                .thenReturn(CLIENT_FP);
            // Fingerprint hits Previous Identity Cert Fingerprint, Identity Hostname matches ...
            stubIdentityMatch(certUtils, CLIENT_FP, CURRENT_IDENTITY_FP, false);
            stubIdentityMatch(certUtils, CLIENT_FP, PREVIOUS_IDENTITY_FP, true);
            stubSingleBadge();
            // ... but the certificate URI SAN (v2.0.0) differs from the Badge Entry ATI Name (v1.0.0).
            when(transparencyClient.getTransparencyLogByPath(TEST_TL_PATH))
                .thenReturn(registration("ACTIVE", CURRENT_IDENTITY_FP, PREVIOUS_IDENTITY_FP));

            ClientVerificationResult result = verificationService.verifyClient(mockCertificate);

            assertThat(result.getStatus()).isEqualTo(VerificationStatus.ATI_NAME_MISMATCH);
        }
    }

    // ==================== No renewal window ====================

    @Test
    @DisplayName("Missing Previous Identity Cert Fingerprint: current identity match is still VERIFIED")
    void missingPreviousIdentityMatchesCurrentOnly() {
        try (MockedStatic<CertificateUtils> certUtils = mockStatic(CertificateUtils.class)) {
            stubClientCert(certUtils, CLIENT_FP);
            stubIdentityMatch(certUtils, CLIENT_FP, CURRENT_IDENTITY_FP, true);
            stubSingleBadge();
            when(transparencyClient.getTransparencyLogByPath(TEST_TL_PATH))
                .thenReturn(registration("ACTIVE", CURRENT_IDENTITY_FP, null));

            ClientVerificationResult result = verificationService.verifyClient(mockCertificate);

            assertThat(result.getStatus()).isEqualTo(VerificationStatus.VERIFIED);
        }
    }

    @Test
    @DisplayName("Blank Previous Identity Cert Fingerprint means no identity renewal window")
    void blankPreviousIdentityMeansNoRenewalWindow() {
        try (MockedStatic<CertificateUtils> certUtils = mockStatic(CertificateUtils.class)) {
            stubClientCert(certUtils, CLIENT_FP);
            stubIdentityMatch(certUtils, CLIENT_FP, CURRENT_IDENTITY_FP, false);
            stubSingleBadge();
            when(transparencyClient.getTransparencyLogByPath(TEST_TL_PATH))
                .thenReturn(registration("ACTIVE", CURRENT_IDENTITY_FP, "   "));

            ClientVerificationResult result = verificationService.verifyClient(mockCertificate);

            assertThat(result.getStatus()).isEqualTo(VerificationStatus.FINGERPRINT_MISMATCH);
        }
    }

    // ==================== Fingerprint mismatch / cross-role ====================

    @Test
    @DisplayName("Fingerprint matching neither current nor previous identity is FINGERPRINT_MISMATCH")
    void matchesNeitherCurrentNorPreviousIdentityIsFingerprintMismatch() {
        try (MockedStatic<CertificateUtils> certUtils = mockStatic(CertificateUtils.class)) {
            stubClientCert(certUtils, CLIENT_FP);
            stubIdentityMatch(certUtils, CLIENT_FP, CURRENT_IDENTITY_FP, false);
            stubIdentityMatch(certUtils, CLIENT_FP, PREVIOUS_IDENTITY_FP, false);
            stubSingleBadge();
            when(transparencyClient.getTransparencyLogByPath(TEST_TL_PATH))
                .thenReturn(registration("ACTIVE", CURRENT_IDENTITY_FP, PREVIOUS_IDENTITY_FP));

            ClientVerificationResult result = verificationService.verifyClient(mockCertificate);

            assertThat(result.getStatus()).isEqualTo(VerificationStatus.FINGERPRINT_MISMATCH);
        }
    }

    @Test
    @DisplayName("A Previous Server Cert Fingerprint never satisfies identity matching (same-role OR)")
    void serverPreviousFingerprintDoesNotSatisfyIdentityMatch() {
        try (MockedStatic<CertificateUtils> certUtils = mockStatic(CertificateUtils.class)) {
            stubClientCert(certUtils, CLIENT_FP);
            stubIdentityMatch(certUtils, CLIENT_FP, CURRENT_IDENTITY_FP, false);
            stubIdentityMatch(certUtils, CLIENT_FP, PREVIOUS_IDENTITY_FP, false);
            stubSingleBadge();
            // The presented fingerprint equals the Previous Server Cert Fingerprint, not any identity value.
            when(transparencyClient.getTransparencyLogByPath(TEST_TL_PATH))
                .thenReturn(registration("ACTIVE", CURRENT_SERVER_FP, CLIENT_FP,
                    CURRENT_IDENTITY_FP, PREVIOUS_IDENTITY_FP));

            ClientVerificationResult result = verificationService.verifyClient(mockCertificate);

            assertThat(result.getStatus()).isEqualTo(VerificationStatus.FINGERPRINT_MISMATCH);
        }
    }

    @Test
    @DisplayName("Entry missing current Identity Cert Fingerprint is not a match even if previous is set")
    void missingCurrentIdentityNotAMatchEvenIfPreviousSet() {
        try (MockedStatic<CertificateUtils> certUtils = mockStatic(CertificateUtils.class)) {
            stubClientCert(certUtils, CLIENT_FP);
            // Previous would match, but the required current Identity Cert Fingerprint is absent.
            stubIdentityMatch(certUtils, CLIENT_FP, PREVIOUS_IDENTITY_FP, true);
            stubSingleBadge();
            when(transparencyClient.getTransparencyLogByPath(TEST_TL_PATH))
                .thenReturn(registration("ACTIVE", null, PREVIOUS_IDENTITY_FP));

            ClientVerificationResult result = verificationService.verifyClient(mockCertificate);

            assertThat(result.getStatus()).isNotIn(
                VerificationStatus.VERIFIED, VerificationStatus.DEPRECATED_OK);
            assertThat(result.getStatus()).isEqualTo(VerificationStatus.FINGERPRINT_MISMATCH);
        }
    }

    // ==================== Duplicate fill ====================

    @Test
    @DisplayName("Previous Identity Cert Fingerprint equal to current still matches (not malformed)")
    void previousEqualsCurrentIdentityStillMatches() {
        try (MockedStatic<CertificateUtils> certUtils = mockStatic(CertificateUtils.class)) {
            stubClientCert(certUtils, CLIENT_FP);
            stubIdentityMatch(certUtils, CLIENT_FP, CLIENT_FP, true);
            stubSingleBadge();
            when(transparencyClient.getTransparencyLogByPath(TEST_TL_PATH))
                .thenReturn(registration("ACTIVE", CLIENT_FP, CLIENT_FP));

            ClientVerificationResult result = verificationService.verifyClient(mockCertificate);

            assertThat(result.getStatus()).isEqualTo(VerificationStatus.VERIFIED);
        }
    }

    // ==================== Convenience accessors ====================

    @Test
    @DisplayName("Current Identity Cert Fingerprint accessors still return the current value only")
    void currentIdentityAccessorStillReturnsCurrentOnly() {
        try (MockedStatic<CertificateUtils> certUtils = mockStatic(CertificateUtils.class)) {
            stubClientCert(certUtils, CLIENT_FP);
            stubIdentityMatch(certUtils, CLIENT_FP, CURRENT_IDENTITY_FP, false);
            stubIdentityMatch(certUtils, CLIENT_FP, PREVIOUS_IDENTITY_FP, true);
            stubSingleBadge();
            when(transparencyClient.getTransparencyLogByPath(TEST_TL_PATH))
                .thenReturn(registration("ACTIVE", CURRENT_IDENTITY_FP, PREVIOUS_IDENTITY_FP));

            ClientVerificationResult result = verificationService.verifyClient(mockCertificate);

            assertThat(result.getStatus()).isEqualTo(VerificationStatus.VERIFIED);
            assertThat(result.getExpectedIdentityCertFingerprint()).isEqualTo(CURRENT_IDENTITY_FP);
            assertThat(result.getRegistration().getIdentityCertFingerprint())
                .isEqualTo(CURRENT_IDENTITY_FP)
                .isNotEqualTo(PREVIOUS_IDENTITY_FP);
            assertThat(result.getRegistration().getPreviousIdentityCertFingerprint())
                .isEqualTo(PREVIOUS_IDENTITY_FP);
        }
    }

    // ==================== Role separation on the server path ====================

    @Test
    @DisplayName("Only Previous Identity Cert Fingerprint present does not change server-role matching")
    void onlyIdentityPreviousDoesNotChangeServerMatching() {
        // verifyServer uses real CertificateUtils; the entry carries a previous identity
        // fingerprint but no previous server fingerprint, so the server allowed set stays current-only.
        stubSingleBadge();
        when(transparencyClient.getTransparencyLogByPath(TEST_TL_PATH))
            .thenReturn(registration("ACTIVE", CURRENT_SERVER_FP, null,
                CURRENT_IDENTITY_FP, PREVIOUS_IDENTITY_FP));

        ServerVerificationResult result = verificationService.verifyServer(TEST_HOSTNAME);

        assertThat(result.getStatus()).isEqualTo(VerificationStatus.VERIFIED);
        assertThat(result.getExpectedServerCertFingerprints())
            .containsExactly(CURRENT_SERVER_FP)
            .doesNotContain(PREVIOUS_IDENTITY_FP, CURRENT_IDENTITY_FP);
    }

    // ==================== Helpers ====================

    private void stubClientCert(MockedStatic<CertificateUtils> certUtils, String clientFingerprint) {
        certUtils.when(() -> CertificateUtils.extractAtiName(mockCertificate))
            .thenReturn(Optional.of(TEST_ANS_NAME));
        certUtils.when(() -> CertificateUtils.extractHostFromAtiName(TEST_ANS_NAME))
            .thenReturn(TEST_HOSTNAME);
        certUtils.when(() -> CertificateUtils.computeSha256Fingerprint(mockCertificate))
            .thenReturn(clientFingerprint);
    }

    private void stubIdentityMatch(
            MockedStatic<CertificateUtils> certUtils,
            String clientFingerprint, String expectedFingerprint, boolean matches) {
        certUtils.when(() -> CertificateUtils.fingerprintMatches(clientFingerprint, expectedFingerprint))
            .thenReturn(matches);
    }

    private void stubSingleBadge() {
        RaBadgeRecord badge = RaBadgeRecord.parse(
            "v=ati-badge1; av=1.0.0; u=https://ati-tl.cnnic.cn:8180/tl/agents/" + TEST_AGENT_ID);
        when(raBadgeLookupService.lookupBadges(TEST_HOSTNAME)).thenReturn(List.of(badge));
    }

    private TransparencyLog registration(
            String status, String currentIdentityFingerprint, String previousIdentityFingerprint) {
        return registration(status, CURRENT_SERVER_FP, null,
            currentIdentityFingerprint, previousIdentityFingerprint);
    }

    private TransparencyLog registration(
            String status,
            String currentServerFingerprint,
            String previousServerFingerprint,
            String currentIdentityFingerprint,
            String previousIdentityFingerprint) {
        TransparencyLogAtiV1 payload = new TransparencyLogAtiV1();
        payload.setAgentName(TEST_ANS_NAME);
        payload.setAgentHost(TEST_HOSTNAME);
        payload.setVersion("1.0.0");
        payload.setAgentId(TEST_AGENT_ID);
        payload.setAgentStatus(status);

        TransparencyLogAtiV1.Certificates certs = new TransparencyLogAtiV1.Certificates();
        certs.setServerCertFingerprint(currentServerFingerprint);
        certs.setPreviousServerCertFingerprint(previousServerFingerprint);
        certs.setIdentityCertFingerprint(currentIdentityFingerprint);
        certs.setPreviousIdentityCertFingerprint(previousIdentityFingerprint);
        payload.setCertificates(certs);

        TransparencyLog log = new TransparencyLog();
        log.setStatus(status);
        log.setSchemaVersion("ATI-TL-V1");
        log.setParsedPayload(payload);
        return log;
    }
}
