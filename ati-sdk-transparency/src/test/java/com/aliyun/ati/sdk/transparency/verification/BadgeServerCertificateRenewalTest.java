package com.aliyun.ati.sdk.transparency.verification;

import com.aliyun.ati.sdk.transparency.TransparencyClient;
import com.aliyun.ati.sdk.transparency.dns.RaBadgeLookupService;
import com.aliyun.ati.sdk.transparency.dns.RaBadgeRecord;
import com.aliyun.ati.sdk.transparency.model.TransparencyLog;
import com.aliyun.ati.sdk.transparency.model.TransparencyLogAtiV1;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

class BadgeServerCertificateRenewalTest {

    private static final String TEST_HOSTNAME = "agent.example.com";
    private static final String TEST_AGENT_ID = "6bf2b7a9-1383-4e33-a945-845f34af7526";
    private static final String TEST_TL_PATH = "/tl/agents/" + TEST_AGENT_ID;
    private static final String SECOND_AGENT_ID = "22222222-2222-2222-2222-222222222222";
    private static final String SECOND_TL_PATH = "/tl/agents/" + SECOND_AGENT_ID;
    private static final String TEST_IDENTITY_FP = "SHA256:a1b2c3d4e5f6g7h8";
    private static final String TEST_ANS_NAME = "ati://v1.0.0.agent.example.com";
    private static final String CURRENT_SERVER_FP = "SHA-256:currentservercertfingerprint01";
    private static final String CURRENT_SERVER_FP_SHA256_PREFIX = "SHA256:currentservercertfingerprint01";
    private static final String PREVIOUS_SERVER_FP = "SHA-256:previousservercertfingerprint01";

    @Mock
    private TransparencyClient transparencyClient;

    @Mock
    private RaBadgeLookupService raBadgeLookupService;

    private BadgeVerificationService verificationService;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        verificationService = BadgeVerificationService.builder()
            .transparencyClient(transparencyClient)
            .raBadgeLookupService(raBadgeLookupService)
            .build();
    }

    @Test
    @DisplayName("ACTIVE Entry with Previous Server Cert Fingerprint contributes current and previous server fingerprints")
    void activeEntryWithPreviousContributesCurrentAndPrevious() {
        stubSingleBadge();
        when(transparencyClient.getTransparencyLogByPath(TEST_TL_PATH))
            .thenReturn(registration("ACTIVE", CURRENT_SERVER_FP, PREVIOUS_SERVER_FP));

        ServerVerificationResult result = verificationService.verifyServer(TEST_HOSTNAME);

        assertThat(result.getStatus()).isEqualTo(VerificationStatus.VERIFIED);
        assertThat(result.getExpectedServerCertFingerprints())
            .containsExactlyInAnyOrder(CURRENT_SERVER_FP, PREVIOUS_SERVER_FP);
    }

    @Test
    @DisplayName("Blank Previous Server Cert Fingerprint means no server renewal window")
    void blankPreviousContributesCurrentOnly() {
        stubSingleBadge();
        when(transparencyClient.getTransparencyLogByPath(TEST_TL_PATH))
            .thenReturn(registration("ACTIVE", CURRENT_SERVER_FP, "  "));

        ServerVerificationResult result = verificationService.verifyServer(TEST_HOSTNAME);

        assertThat(result.getStatus()).isEqualTo(VerificationStatus.VERIFIED);
        assertThat(result.getExpectedServerCertFingerprints())
            .containsExactly(CURRENT_SERVER_FP);
    }

    @Test
    @DisplayName("Previous Server Cert Fingerprint equal to current is a one-element allowed set")
    void previousEqualToCurrentIsStillAMatch() {
        stubSingleBadge();
        when(transparencyClient.getTransparencyLogByPath(TEST_TL_PATH))
            .thenReturn(registration("ACTIVE", CURRENT_SERVER_FP, CURRENT_SERVER_FP));

        ServerVerificationResult result = verificationService.verifyServer(TEST_HOSTNAME);

        assertThat(result.getStatus()).isEqualTo(VerificationStatus.VERIFIED);
        assertThat(result.getExpectedServerCertFingerprints())
            .containsExactly(CURRENT_SERVER_FP);
    }

    @Test
    @DisplayName("Previous Server Cert Fingerprint equal to current after prefix normalization is a one-element allowed set")
    void previousEqualToCurrentAfterPrefixNormalizationIsStillAMatch() {
        stubSingleBadge();
        when(transparencyClient.getTransparencyLogByPath(TEST_TL_PATH))
            .thenReturn(registration("ACTIVE", CURRENT_SERVER_FP, CURRENT_SERVER_FP_SHA256_PREFIX));

        ServerVerificationResult result = verificationService.verifyServer(TEST_HOSTNAME);

        assertThat(result.getStatus()).isEqualTo(VerificationStatus.VERIFIED);
        assertThat(result.getExpectedServerCertFingerprints())
            .containsExactly(CURRENT_SERVER_FP);
    }

    @Test
    @DisplayName("Missing Previous Server Cert Fingerprint contributes only the current Server Cert Fingerprint")
    void missingPreviousContributesCurrentOnly() {
        stubSingleBadge();
        when(transparencyClient.getTransparencyLogByPath(TEST_TL_PATH))
            .thenReturn(registration("ACTIVE", CURRENT_SERVER_FP, null));

        ServerVerificationResult result = verificationService.verifyServer(TEST_HOSTNAME);

        assertThat(result.getStatus()).isEqualTo(VerificationStatus.VERIFIED);
        assertThat(result.getExpectedServerCertFingerprints())
            .containsExactly(CURRENT_SERVER_FP);
    }

    @Test
    @DisplayName("Entry missing current Server Cert Fingerprint contributes nothing even if Previous Server Cert Fingerprint is set")
    void missingCurrentContributesNoServerFingerprints() {
        stubSingleBadge();
        when(transparencyClient.getTransparencyLogByPath(TEST_TL_PATH))
            .thenReturn(registration("ACTIVE", null, PREVIOUS_SERVER_FP));

        ServerVerificationResult result = verificationService.verifyServer(TEST_HOSTNAME);

        assertThat(result.getExpectedServerCertFingerprints()).isEmpty();
        assertThat(result.getStatus()).isNotIn(
            VerificationStatus.VERIFIED, VerificationStatus.DEPRECATED_OK);
    }

    @Test
    @DisplayName("Two ACTIVE Entries each with current and Previous Server Cert Fingerprint union all four fingerprints")
    void twoActiveEntriesUnionCurrentAndPrevious() {
        String current2 = "SHA-256:currentservercertfingerprint02";
        String previous2 = "SHA-256:previousservercertfingerprint02";
        stubTwoBadges();
        when(transparencyClient.getTransparencyLogByPath(TEST_TL_PATH))
            .thenReturn(registration("ACTIVE", CURRENT_SERVER_FP, PREVIOUS_SERVER_FP));
        when(transparencyClient.getTransparencyLogByPath(SECOND_TL_PATH))
            .thenReturn(registration("ACTIVE", current2, previous2));

        ServerVerificationResult result = verificationService.verifyServer(TEST_HOSTNAME);

        assertThat(result.getStatus()).isEqualTo(VerificationStatus.VERIFIED);
        assertThat(result.getExpectedServerCertFingerprints())
            .containsExactlyInAnyOrder(
                CURRENT_SERVER_FP, PREVIOUS_SERVER_FP, current2, previous2);
    }

    @Test
    @DisplayName("REVOKED Entry Previous Server Cert Fingerprint is not in the allowed set")
    void revokedEntryPreviousIsNotAllowed() {
        stubTwoBadges();
        when(transparencyClient.getTransparencyLogByPath(TEST_TL_PATH))
            .thenReturn(registration("REVOKED", "SHA-256:revokedcurrentserverfp0001", PREVIOUS_SERVER_FP));
        when(transparencyClient.getTransparencyLogByPath(SECOND_TL_PATH))
            .thenReturn(registration("ACTIVE", CURRENT_SERVER_FP, null));

        ServerVerificationResult result = verificationService.verifyServer(TEST_HOSTNAME);

        assertThat(result.getStatus()).isEqualTo(VerificationStatus.VERIFIED);
        assertThat(result.getExpectedServerCertFingerprints())
            .containsExactly(CURRENT_SERVER_FP)
            .doesNotContain(PREVIOUS_SERVER_FP);
    }

    @Test
    @DisplayName("EXPIRED Entry Previous Server Cert Fingerprint is not in the allowed set")
    void expiredEntryPreviousIsNotAllowed() {
        stubTwoBadges();
        when(transparencyClient.getTransparencyLogByPath(TEST_TL_PATH))
            .thenReturn(registration("EXPIRED", "SHA-256:expiredcurrentserverfp0001", PREVIOUS_SERVER_FP));
        when(transparencyClient.getTransparencyLogByPath(SECOND_TL_PATH))
            .thenReturn(registration("ACTIVE", CURRENT_SERVER_FP, null));

        ServerVerificationResult result = verificationService.verifyServer(TEST_HOSTNAME);

        assertThat(result.getStatus()).isEqualTo(VerificationStatus.VERIFIED);
        assertThat(result.getExpectedServerCertFingerprints())
            .containsExactly(CURRENT_SERVER_FP)
            .doesNotContain(PREVIOUS_SERVER_FP);
    }

    @Test
    @DisplayName("Current Server Cert Fingerprint accessor still returns current only")
    void currentFingerprintAccessorIgnoresPrevious() {
        stubSingleBadge();
        when(transparencyClient.getTransparencyLogByPath(TEST_TL_PATH))
            .thenReturn(registration("ACTIVE", CURRENT_SERVER_FP, PREVIOUS_SERVER_FP));

        ServerVerificationResult result = verificationService.verifyServer(TEST_HOSTNAME);

        assertThat(result.getRegistration().getServerCertFingerprint())
            .isEqualTo(CURRENT_SERVER_FP)
            .isNotEqualTo(PREVIOUS_SERVER_FP);
        assertThat(result.getRegistration().getPreviousServerCertFingerprint())
            .isEqualTo(PREVIOUS_SERVER_FP);
    }

    @Test
    @DisplayName("DEPRECATED Entry with Previous Server Cert Fingerprint is DEPRECATED_OK and includes both fingerprints")
    void deprecatedEntryWithPreviousKeepsDeprecatedOk() {
        stubSingleBadge();
        when(transparencyClient.getTransparencyLogByPath(TEST_TL_PATH))
            .thenReturn(registration("DEPRECATED", CURRENT_SERVER_FP, PREVIOUS_SERVER_FP));

        ServerVerificationResult result = verificationService.verifyServer(TEST_HOSTNAME);

        assertThat(result.getStatus()).isEqualTo(VerificationStatus.DEPRECATED_OK);
        assertThat(result.getExpectedServerCertFingerprints())
            .containsExactlyInAnyOrder(CURRENT_SERVER_FP, PREVIOUS_SERVER_FP);
    }

    @Test
    @DisplayName("WARNING Entry with Previous Server Cert Fingerprint is VERIFIED and includes both fingerprints")
    void warningEntryWithPreviousIsVerified() {
        stubSingleBadge();
        when(transparencyClient.getTransparencyLogByPath(TEST_TL_PATH))
            .thenReturn(registration("WARNING", CURRENT_SERVER_FP, PREVIOUS_SERVER_FP));

        ServerVerificationResult result = verificationService.verifyServer(TEST_HOSTNAME);

        assertThat(result.getStatus()).isEqualTo(VerificationStatus.VERIFIED);
        assertThat(result.getExpectedServerCertFingerprints())
            .containsExactlyInAnyOrder(CURRENT_SERVER_FP, PREVIOUS_SERVER_FP);
    }

    private void stubSingleBadge() {
        RaBadgeRecord badge = RaBadgeRecord.parse(
            "v=ati-badge1; av=1.0.0; u=https://ati-tl.cnnic.cn:8180/tl/agents/" + TEST_AGENT_ID);
        when(raBadgeLookupService.lookupBadges(TEST_HOSTNAME)).thenReturn(List.of(badge));
    }

    private void stubTwoBadges() {
        when(raBadgeLookupService.lookupBadges(TEST_HOSTNAME)).thenReturn(List.of(
            RaBadgeRecord.parse(
                "v=ati-badge1; av=1.0.0; u=https://ati-tl.cnnic.cn:8180/tl/agents/" + TEST_AGENT_ID),
            RaBadgeRecord.parse(
                "v=ati-badge1; av=1.0.1; u=https://ati-tl.cnnic.cn:8180/tl/agents/" + SECOND_AGENT_ID)
        ));
    }

    private TransparencyLog registration(
            String status, String currentFingerprint, String previousServerCertFingerprint) {
        TransparencyLogAtiV1 payload = new TransparencyLogAtiV1();
        payload.setAgentName(TEST_ANS_NAME);
        payload.setAgentHost(TEST_HOSTNAME);
        payload.setVersion("1.0.0");
        payload.setAgentId("some-uuid");
        payload.setAgentStatus(status);

        TransparencyLogAtiV1.Certificates certs = new TransparencyLogAtiV1.Certificates();
        certs.setServerCertFingerprint(currentFingerprint);
        certs.setPreviousServerCertFingerprint(previousServerCertFingerprint);
        certs.setIdentityCertFingerprint(TEST_IDENTITY_FP);
        payload.setCertificates(certs);

        TransparencyLog log = new TransparencyLog();
        log.setStatus(status);
        log.setSchemaVersion("ATI-TL-V1");
        log.setParsedPayload(payload);
        return log;
    }
}
