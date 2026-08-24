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
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.mockito.Mockito.mockStatic;

/**
 * Unit tests for client certificate verification via mTLS.
 * Tests the {@link BadgeVerificationService#verifyClient(X509Certificate)} method.
 */
class ClientVerificationTest {

    private static final String TEST_HOSTNAME = "agent.example.com";
    private static final String TEST_AGENT_ID = "6bf2b7a9-1383-4e33-a945-845f34af7526";
    private static final String TEST_TL_PATH = "/tl/agents/" + TEST_AGENT_ID;
    private static final String TEST_ANS_NAME = "ati://v1.0.0.agent.example.com";
    private static final String TEST_FINGERPRINT =
            "SHA256:a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2";

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

    // ==================== All Fields Match, ACTIVE ====================

    @Test
    @DisplayName("Should pass when all fields match with ACTIVE status")
    void shouldPassWhenAllFieldsMatchWithActiveStatus() {
        try (MockedStatic<CertificateUtils> certUtils = mockStatic(CertificateUtils.class)) {
            // Given - mock certificate utilities
            certUtils.when(() -> CertificateUtils.extractAtiName(mockCertificate))
                .thenReturn(Optional.of(TEST_ANS_NAME));
            certUtils.when(() -> CertificateUtils.extractHostFromAtiName(TEST_ANS_NAME))
                .thenReturn(TEST_HOSTNAME);
            certUtils.when(() -> CertificateUtils.getCommonName(mockCertificate))
                .thenReturn(TEST_HOSTNAME);
            certUtils.when(() -> CertificateUtils.computeSha256Fingerprint(mockCertificate))
                .thenReturn(TEST_FINGERPRINT);
            certUtils.when(() -> CertificateUtils.fingerprintMatches(TEST_FINGERPRINT, TEST_FINGERPRINT))
                .thenReturn(true);

            // Mock badge lookup
            RaBadgeRecord badge = RaBadgeRecord.parse(
                "v=ati-badge1; av=1.0.0; u=https://ati-tl.cnnic.cn:8180/tl/agents/" + TEST_AGENT_ID);
            when(raBadgeLookupService.lookupBadges(TEST_HOSTNAME)).thenReturn(List.of(badge));

            // Mock registration with matching fingerprint
            TransparencyLog registration = createMockRegistration("ACTIVE", TEST_FINGERPRINT);
            when(transparencyClient.getTransparencyLogByPath(TEST_TL_PATH)).thenReturn(registration);

            // When
            ClientVerificationResult result = verificationService.verifyClient(mockCertificate);

            // Then
            assertThat(result.getStatus()).isEqualTo(VerificationStatus.VERIFIED);
            assertThat(result.getExpectedIdentityCertFingerprint()).isEqualTo(TEST_FINGERPRINT);
            assertThat(result.getExpectedAtiName()).isEqualTo(TEST_ANS_NAME);
            assertThat(result.getExpectedAgentHost()).isEqualTo(TEST_HOSTNAME);
        }
    }

    // ==================== No URI SAN in Cert ====================

    @Test
    @DisplayName("Should fail when cert has no URI SAN (ATI name required per spec)")
    void shouldFailWhenCertHasNoUriSan() {
        try (MockedStatic<CertificateUtils> certUtils = mockStatic(CertificateUtils.class)) {
            // Given - mock certificate with NO URI SAN
            certUtils.when(() -> CertificateUtils.extractAtiName(mockCertificate))
                .thenReturn(Optional.empty()); // No URI SAN

            // When
            ClientVerificationResult result = verificationService.verifyClient(mockCertificate);

            // Then - should fail because URI SAN is required for badge lookup
            assertThat(result.getStatus()).isEqualTo(VerificationStatus.LOOKUP_FAILED);
            assertThat(result.getWarningMessage()).contains("ATI URI SAN");
        }
    }

    // ==================== DNS SAN Mismatch ====================

    @Test
    @DisplayName("Should reject when URI SAN agentHost does not match registration agent.host")
    void shouldRejectWhenAgentHostMismatchesRegistration() {
        try (MockedStatic<CertificateUtils> certUtils = mockStatic(CertificateUtils.class)) {
            // Given - URI SAN resolves to a different agentHost than the registration record
            String differentAtiName = "ati://v1.0.0.different-agent.example.com";
            String differentAgentHost = "different-agent.example.com";
            certUtils.when(() -> CertificateUtils.extractAtiName(mockCertificate))
                .thenReturn(Optional.of(differentAtiName));
            certUtils.when(() -> CertificateUtils.extractHostFromAtiName(differentAtiName))
                .thenReturn(differentAgentHost);
            certUtils.when(() -> CertificateUtils.computeSha256Fingerprint(mockCertificate))
                .thenReturn(TEST_FINGERPRINT);
            certUtils.when(() -> CertificateUtils.fingerprintMatches(TEST_FINGERPRINT, TEST_FINGERPRINT))
                .thenReturn(true);

            RaBadgeRecord badge = RaBadgeRecord.parse(
                "v=ati-badge1; av=1.0.0; u=https://ati-tl.cnnic.cn:8180/tl/agents/" + TEST_AGENT_ID);
            when(raBadgeLookupService.lookupBadges(differentAgentHost)).thenReturn(List.of(badge));

            TransparencyLog registration = createMockRegistration("ACTIVE", TEST_FINGERPRINT);
            when(transparencyClient.getTransparencyLogByPath(TEST_TL_PATH)).thenReturn(registration);

            // When
            ClientVerificationResult result = verificationService.verifyClient(mockCertificate);

            // Then
            assertThat(result.getStatus()).isEqualTo(VerificationStatus.HOSTNAME_MISMATCH);
        }
    }

    @Test
    @DisplayName("Should pass Shared Domain Mode when URI SAN matches agentSubHost not agentHost")
    void shouldPassSharedDomainWhenUriSanMatchesAgentSubHost() {
        String identityHost = "abc123.bailian.aliyun.com";
        String accessHost = "bailian.aliyun.com";
        String atiName = "ati://v1.0.0." + identityHost;
        try (MockedStatic<CertificateUtils> certUtils = mockStatic(CertificateUtils.class)) {
            certUtils.when(() -> CertificateUtils.extractAtiName(mockCertificate))
                .thenReturn(Optional.of(atiName));
            certUtils.when(() -> CertificateUtils.extractHostFromAtiName(atiName))
                .thenReturn(identityHost);
            certUtils.when(() -> CertificateUtils.computeSha256Fingerprint(mockCertificate))
                .thenReturn(TEST_FINGERPRINT);
            certUtils.when(() -> CertificateUtils.fingerprintMatches(TEST_FINGERPRINT, TEST_FINGERPRINT))
                .thenReturn(true);

            RaBadgeRecord badge = RaBadgeRecord.parse(
                "v=ati-badge1; av=1.0.0; u=https://ati-tl.cnnic.cn:8180/tl/agents/" + TEST_AGENT_ID);
            when(raBadgeLookupService.lookupBadges(identityHost)).thenReturn(List.of(badge));

            TransparencyLog registration = createSharedDomainRegistration(
                "ACTIVE", TEST_FINGERPRINT, atiName, accessHost, identityHost);
            when(transparencyClient.getTransparencyLogByPath(TEST_TL_PATH)).thenReturn(registration);

            ClientVerificationResult result = verificationService.verifyClient(mockCertificate);

            assertThat(result.getStatus()).isEqualTo(VerificationStatus.VERIFIED);
            assertThat(result.getExpectedAgentHost()).isEqualTo(identityHost);
        }
    }

    @Test
    @DisplayName("Should skip hostname-mismatched Badge and match a later Shared Domain entry")
    void shouldSkipHostnameMismatchAndMatchLaterSharedDomainEntry() {
        String identityHost = "abc123.bailian.aliyun.com";
        String accessHost = "bailian.aliyun.com";
        String atiName = "ati://v1.0.0." + identityHost;
        String otherAgentId = "aaaaaaaa-1111-1111-1111-aaaaaaaaaaaa";
        try (MockedStatic<CertificateUtils> certUtils = mockStatic(CertificateUtils.class)) {
            certUtils.when(() -> CertificateUtils.extractAtiName(mockCertificate))
                .thenReturn(Optional.of(atiName));
            certUtils.when(() -> CertificateUtils.extractHostFromAtiName(atiName))
                .thenReturn(identityHost);
            certUtils.when(() -> CertificateUtils.computeSha256Fingerprint(mockCertificate))
                .thenReturn(TEST_FINGERPRINT);
            certUtils.when(() -> CertificateUtils.fingerprintMatches(TEST_FINGERPRINT, TEST_FINGERPRINT))
                .thenReturn(true);

            RaBadgeRecord wrongBadge = RaBadgeRecord.parse(
                "v=ati-badge1; av=1.0.0; u=https://ati-tl.cnnic.cn:8180/tl/agents/" + otherAgentId);
            RaBadgeRecord matchingBadge = RaBadgeRecord.parse(
                "v=ati-badge1; av=1.0.0; u=https://ati-tl.cnnic.cn:8180/tl/agents/" + TEST_AGENT_ID);
            when(raBadgeLookupService.lookupBadges(identityHost))
                .thenReturn(List.of(wrongBadge, matchingBadge));

            TransparencyLog wrongIdentity = createSharedDomainRegistration(
                "ACTIVE", TEST_FINGERPRINT, atiName, accessHost, "other.bailian.aliyun.com");
            TransparencyLog matching = createSharedDomainRegistration(
                "ACTIVE", TEST_FINGERPRINT, atiName, accessHost, identityHost);
            when(transparencyClient.getTransparencyLogByPath("/tl/agents/" + otherAgentId))
                .thenReturn(wrongIdentity);
            when(transparencyClient.getTransparencyLogByPath(TEST_TL_PATH)).thenReturn(matching);

            ClientVerificationResult result = verificationService.verifyClient(mockCertificate);

            assertThat(result.getStatus()).isEqualTo(VerificationStatus.VERIFIED);
            assertThat(result.getExpectedAgentHost()).isEqualTo(identityHost);
        }
    }

    // ==================== URI SAN Mismatch ====================

    @Test
    @DisplayName("Should reject when URI SAN does not match atiName")
    void shouldRejectWhenUriSanMismatchesAtiName() {
        try (MockedStatic<CertificateUtils> certUtils = mockStatic(CertificateUtils.class)) {
            // Given - mock certificate with DIFFERENT ANS name
            String differentAtiName = "ati://v2.0.0.agent.example.com";
            certUtils.when(() -> CertificateUtils.extractAtiName(mockCertificate))
                .thenReturn(Optional.of(differentAtiName)); // Different version
            certUtils.when(() -> CertificateUtils.extractHostFromAtiName(differentAtiName))
                .thenReturn(TEST_HOSTNAME);
            certUtils.when(() -> CertificateUtils.getCommonName(mockCertificate))
                .thenReturn(TEST_HOSTNAME);
            certUtils.when(() -> CertificateUtils.computeSha256Fingerprint(mockCertificate))
                .thenReturn(TEST_FINGERPRINT);
            certUtils.when(() -> CertificateUtils.fingerprintMatches(TEST_FINGERPRINT, TEST_FINGERPRINT))
                .thenReturn(true);

            // Mock badge lookup
            RaBadgeRecord badge = RaBadgeRecord.parse(
                "v=ati-badge1; av=1.0.0; u=https://ati-tl.cnnic.cn:8180/tl/agents/" + TEST_AGENT_ID);
            when(raBadgeLookupService.lookupBadges(TEST_HOSTNAME)).thenReturn(List.of(badge));

            // Mock registration with DIFFERENT atiName
            TransparencyLog registration = createMockRegistration("ACTIVE", TEST_FINGERPRINT);
            // atiName in registration is TEST_ANS_NAME (v1.0.0) but cert has v2.0.0
            when(transparencyClient.getTransparencyLogByPath(TEST_TL_PATH)).thenReturn(registration);

            // When
            ClientVerificationResult result = verificationService.verifyClient(mockCertificate);

            // Then - should fail with ANS name mismatch
            assertThat(result.getStatus()).isEqualTo(VerificationStatus.ATI_NAME_MISMATCH);
        }
    }

    // ==================== Fingerprint Mismatch ====================

    @Test
    @DisplayName("Should reject when fingerprint does not match identityCert")
    void shouldRejectWhenFingerprintMismatchesIdentityCert() {
        try (MockedStatic<CertificateUtils> certUtils = mockStatic(CertificateUtils.class)) {
            // Given
            String differentFingerprint = "SHA256:different1234567890abcdef1234567890abcdef1234567890abcdef12345678";
            certUtils.when(() -> CertificateUtils.extractAtiName(mockCertificate))
                .thenReturn(Optional.of(TEST_ANS_NAME));
            certUtils.when(() -> CertificateUtils.extractHostFromAtiName(TEST_ANS_NAME))
                .thenReturn(TEST_HOSTNAME);
            certUtils.when(() -> CertificateUtils.getCommonName(mockCertificate))
                .thenReturn(TEST_HOSTNAME);
            certUtils.when(() -> CertificateUtils.computeSha256Fingerprint(mockCertificate))
                .thenReturn(differentFingerprint);
            // Fingerprints DON'T match
            certUtils.when(() -> CertificateUtils.fingerprintMatches(differentFingerprint, TEST_FINGERPRINT))
                .thenReturn(false);

            // Mock badge lookup
            RaBadgeRecord badge = RaBadgeRecord.parse(
                "v=ati-badge1; av=1.0.0; u=https://ati-tl.cnnic.cn:8180/tl/agents/" + TEST_AGENT_ID);
            when(raBadgeLookupService.lookupBadges(TEST_HOSTNAME)).thenReturn(List.of(badge));

            // Mock registration with DIFFERENT fingerprint
            TransparencyLog registration = createMockRegistration("ACTIVE", TEST_FINGERPRINT);
            when(transparencyClient.getTransparencyLogByPath(TEST_TL_PATH)).thenReturn(registration);

            // When
            ClientVerificationResult result = verificationService.verifyClient(mockCertificate);

            // Then - should fail with fingerprint mismatch
            assertThat(result.getStatus()).isEqualTo(VerificationStatus.FINGERPRINT_MISMATCH);
        }
    }

    // ==================== DEPRECATED Status ====================

    @Test
    @DisplayName("Should pass with warning when all fields match but status is DEPRECATED")
    void shouldPassWithWarningWhenDeprecatedStatus() {
        try (MockedStatic<CertificateUtils> certUtils = mockStatic(CertificateUtils.class)) {
            // Given
            certUtils.when(() -> CertificateUtils.extractAtiName(mockCertificate))
                .thenReturn(Optional.of(TEST_ANS_NAME));
            certUtils.when(() -> CertificateUtils.extractHostFromAtiName(TEST_ANS_NAME))
                .thenReturn(TEST_HOSTNAME);
            certUtils.when(() -> CertificateUtils.getCommonName(mockCertificate))
                .thenReturn(TEST_HOSTNAME);
            certUtils.when(() -> CertificateUtils.computeSha256Fingerprint(mockCertificate))
                .thenReturn(TEST_FINGERPRINT);
            certUtils.when(() -> CertificateUtils.fingerprintMatches(TEST_FINGERPRINT, TEST_FINGERPRINT))
                .thenReturn(true);

            // Mock badge lookup
            RaBadgeRecord badge = RaBadgeRecord.parse(
                "v=ati-badge1; av=1.0.0; u=https://ati-tl.cnnic.cn:8180/tl/agents/" + TEST_AGENT_ID);
            when(raBadgeLookupService.lookupBadges(TEST_HOSTNAME)).thenReturn(List.of(badge));

            // Mock registration with DEPRECATED status
            TransparencyLog registration = createMockRegistration("DEPRECATED", TEST_FINGERPRINT);
            when(transparencyClient.getTransparencyLogByPath(TEST_TL_PATH)).thenReturn(registration);

            // When
            ClientVerificationResult result = verificationService.verifyClient(mockCertificate);

            // Then - should pass with DEPRECATED_OK status
            assertThat(result.getStatus()).isEqualTo(VerificationStatus.DEPRECATED_OK);
            assertThat(result.getWarningMessage()).contains("deprecated");
        }
    }

    // ==================== EXPIRED Status ====================

    @Test
    @DisplayName("Should return REGISTRATION_INVALID when status is EXPIRED")
    void shouldReturnRegistrationInvalidWhenExpiredStatus() {
        try (MockedStatic<CertificateUtils> certUtils = mockStatic(CertificateUtils.class)) {
            // Given
            certUtils.when(() -> CertificateUtils.extractAtiName(mockCertificate))
                .thenReturn(Optional.of(TEST_ANS_NAME));
            certUtils.when(() -> CertificateUtils.extractHostFromAtiName(TEST_ANS_NAME))
                .thenReturn(TEST_HOSTNAME);
            certUtils.when(() -> CertificateUtils.getCommonName(mockCertificate))
                .thenReturn(TEST_HOSTNAME);
            certUtils.when(() -> CertificateUtils.computeSha256Fingerprint(mockCertificate))
                .thenReturn(TEST_FINGERPRINT);
            certUtils.when(() -> CertificateUtils.fingerprintMatches(TEST_FINGERPRINT, TEST_FINGERPRINT))
                .thenReturn(true);

            // Mock badge lookup
            RaBadgeRecord badge = RaBadgeRecord.parse(
                "v=ati-badge1; av=1.0.0; u=https://ati-tl.cnnic.cn:8180/tl/agents/" + TEST_AGENT_ID);
            when(raBadgeLookupService.lookupBadges(TEST_HOSTNAME)).thenReturn(List.of(badge));

            // Mock registration with EXPIRED status (even though fingerprint matches)
            TransparencyLog registration = createMockRegistration("EXPIRED", TEST_FINGERPRINT);
            when(transparencyClient.getTransparencyLogByPath(TEST_TL_PATH)).thenReturn(registration);

            // When
            ClientVerificationResult result = verificationService.verifyClient(mockCertificate);

            // Then - registration matched but status is invalid
            assertThat(result.getStatus()).isEqualTo(VerificationStatus.REGISTRATION_INVALID);
            assertThat(result.getWarningMessage()).contains("EXPIRED");
        }
    }

    // ==================== No Badge Record ====================

    @Test
    @DisplayName("Should return NOT_ATI_AGENT when no _ati-badge record exists")
    void shouldReturnNotAnsAgentWhenNoBadgeRecord() {
        try (MockedStatic<CertificateUtils> certUtils = mockStatic(CertificateUtils.class)) {
            // Given
            certUtils.when(() -> CertificateUtils.extractAtiName(mockCertificate))
                .thenReturn(Optional.of(TEST_ANS_NAME));
            certUtils.when(() -> CertificateUtils.extractHostFromAtiName(TEST_ANS_NAME))
                .thenReturn(TEST_HOSTNAME);

            // Mock no badge records found
            when(raBadgeLookupService.lookupBadges(TEST_HOSTNAME)).thenReturn(List.of());

            // When
            ClientVerificationResult result = verificationService.verifyClient(mockCertificate);

            // Then
            assertThat(result.getStatus()).isEqualTo(VerificationStatus.NOT_ATI_AGENT);
        }
    }

    // ==================== 4.10 No ATI URI SAN in Certificate ====================

    @Test
    @DisplayName("4.10 Should return LOOKUP_FAILED when certificate has no ATI URI SAN")
    void shouldReturnLookupFailedWhenNoAtiUriSan() {
        try (MockedStatic<CertificateUtils> certUtils = mockStatic(CertificateUtils.class)) {
            // Given - certificate has no ATI URI SAN
            certUtils.when(() -> CertificateUtils.extractAtiName(mockCertificate))
                .thenReturn(Optional.empty());

            // When
            ClientVerificationResult result = verificationService.verifyClient(mockCertificate);

            // Then
            assertThat(result.getStatus()).isEqualTo(VerificationStatus.LOOKUP_FAILED);
            assertThat(result.getWarningMessage()).contains("ATI URI SAN");
        }
    }

    @Test
    @DisplayName("Should path-fetch when Badge TXT u= host is not a Trusted TL Domain")
    void shouldPathFetchWhenBadgeTxtHostIsNotTrustedTlDomain() {
        try (MockedStatic<CertificateUtils> certUtils = mockStatic(CertificateUtils.class)) {
            certUtils.when(() -> CertificateUtils.extractAtiName(mockCertificate))
                .thenReturn(Optional.of(TEST_ANS_NAME));
            certUtils.when(() -> CertificateUtils.extractHostFromAtiName(TEST_ANS_NAME))
                .thenReturn(TEST_HOSTNAME);
            certUtils.when(() -> CertificateUtils.getCommonName(mockCertificate))
                .thenReturn(TEST_HOSTNAME);
            certUtils.when(() -> CertificateUtils.computeSha256Fingerprint(mockCertificate))
                .thenReturn(TEST_FINGERPRINT);
            certUtils.when(() -> CertificateUtils.fingerprintMatches(TEST_FINGERPRINT, TEST_FINGERPRINT))
                .thenReturn(true);

            RaBadgeRecord badge = RaBadgeRecord.parse(
                "v=ati-badge1; av=1.0.0; u=https://evil.example/tl/agents/" + TEST_AGENT_ID);
            when(raBadgeLookupService.lookupBadges(TEST_HOSTNAME)).thenReturn(List.of(badge));
            TransparencyLog registration = createMockRegistration("ACTIVE", TEST_FINGERPRINT);
            when(transparencyClient.getTransparencyLogByPath(TEST_TL_PATH)).thenReturn(registration);

            ClientVerificationResult result = verificationService.verifyClient(mockCertificate);

            assertThat(result.getStatus()).isEqualTo(VerificationStatus.VERIFIED);
            verify(transparencyClient).getTransparencyLogByPath(TEST_TL_PATH);
        }
    }

    // ==================== Helper Methods ====================

    private TransparencyLog createMockRegistration(String status, String fingerprint) {
        return createMockRegistration(status, fingerprint, TEST_ANS_NAME);
    }

    private TransparencyLog createMockRegistration(String status, String fingerprint, String atiName) {
        TransparencyLogAtiV1 payload = new TransparencyLogAtiV1();
        payload.setAgentName(atiName);
        payload.setAgentHost(TEST_HOSTNAME);
        payload.setVersion("1.0.0");
        payload.setAgentId("some-uuid");
        payload.setAgentStatus(status);

        TransparencyLogAtiV1.Certificates certs = new TransparencyLogAtiV1.Certificates();
        certs.setServerCertFingerprint(fingerprint);
        certs.setIdentityCertFingerprint(fingerprint);
        payload.setCertificates(certs);

        TransparencyLog log = new TransparencyLog();
        log.setStatus(status);
        log.setSchemaVersion("ATI-TL-V1");
        log.setParsedPayload(payload);

        return log;
    }

    private TransparencyLog createMockRegistrationNoAtiName(String status, String fingerprint) {
        TransparencyLogAtiV1 payload = new TransparencyLogAtiV1();
        payload.setAgentName(null); // No ATI name
        payload.setAgentHost(TEST_HOSTNAME);
        payload.setVersion("1.0.0");
        payload.setAgentId("some-uuid");
        payload.setAgentStatus(status);

        TransparencyLogAtiV1.Certificates certs = new TransparencyLogAtiV1.Certificates();
        certs.setServerCertFingerprint(fingerprint);
        certs.setIdentityCertFingerprint(fingerprint);
        payload.setCertificates(certs);

        TransparencyLog log = new TransparencyLog();
        log.setStatus(status);
        log.setSchemaVersion("ATI-TL-V1");
        log.setParsedPayload(payload);

        return log;
    }

    private TransparencyLog createSharedDomainRegistration(
            String status, String fingerprint, String atiName, String accessHost, String identityHost) {
        TransparencyLogAtiV1 payload = new TransparencyLogAtiV1();
        payload.setAgentName(atiName);
        payload.setAgentHost(accessHost);
        payload.setAgentSubHost(identityHost);
        payload.setVersion("1.0.0");
        payload.setAgentId("some-uuid");
        payload.setAgentStatus(status);

        TransparencyLogAtiV1.Certificates certs = new TransparencyLogAtiV1.Certificates();
        certs.setServerCertFingerprint(fingerprint);
        certs.setIdentityCertFingerprint(fingerprint);
        payload.setCertificates(certs);

        TransparencyLog log = new TransparencyLog();
        log.setStatus(status);
        log.setSchemaVersion("ATI-TL-V1");
        log.setParsedPayload(payload);

        return log;
    }
}
