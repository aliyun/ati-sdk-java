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
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class BadgeVerificationPathFetchTest {

    private static final String TEST_HOSTNAME = "agent.example.com";
    private static final String TEST_AGENT_ID = "6bf2b7a9-1383-4e33-a945-845f34af7526";
    private static final String TEST_TL_PATH = "/tl/agents/" + TEST_AGENT_ID;
    private static final String TEST_FINGERPRINT = "SHA256:a1b2c3d4e5f6g7h8";
    private static final String TEST_ANS_NAME = "ati://v1.0.0.agent.example.com";

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
    @DisplayName("Should fetch via TransparencyClient path when Badge TXT u= host is not a Trusted TL Domain")
    void shouldFetchViaConfiguredPathWhenBadgeTxtHostIsNotTrustedTlDomain() {
        RaBadgeRecord badge = RaBadgeRecord.parse(
            "v=ati-badge1; av=1.0.0; u=https://evil.example/tl/agents/" + TEST_AGENT_ID);
        when(raBadgeLookupService.lookupBadges(TEST_HOSTNAME)).thenReturn(List.of(badge));
        when(transparencyClient.getTransparencyLogByPath(TEST_TL_PATH))
            .thenReturn(activeRegistration());

        ServerVerificationResult result = verificationService.verifyServer(TEST_HOSTNAME);

        assertThat(result.getStatus()).isEqualTo(VerificationStatus.VERIFIED);
        verify(transparencyClient).getTransparencyLogByPath(TEST_TL_PATH);
        verify(transparencyClient, never()).getAgentTransparencyLog(anyString());
    }

    @Test
    @DisplayName("Should reject path traversal at path fetch, not by treating the Badge TXT u= host as untrusted")
    void shouldRejectPathTraversalAtPathFetchNotTxtHostAllowlist() {
        String traversalPath = "/tl/agents/../../admin";
        RaBadgeRecord badge = RaBadgeRecord.parse(
            "v=ati-badge1; av=1.0.0; u=https://evil.example" + traversalPath);
        when(raBadgeLookupService.lookupBadges(TEST_HOSTNAME)).thenReturn(List.of(badge));
        when(transparencyClient.getTransparencyLogByPath(traversalPath))
            .thenThrow(new IllegalArgumentException("Path traversal detected in tlPath: " + traversalPath));

        ServerVerificationResult result = verificationService.verifyServer(TEST_HOSTNAME);

        assertThat(result.getStatus()).isEqualTo(VerificationStatus.LOOKUP_FAILED);
        verify(transparencyClient).getTransparencyLogByPath(traversalPath);
    }

    private TransparencyLog activeRegistration() {
        TransparencyLogAtiV1 payload = new TransparencyLogAtiV1();
        payload.setAgentName(TEST_ANS_NAME);
        payload.setAgentHost(TEST_HOSTNAME);
        payload.setVersion("1.0.0");
        payload.setAgentId(TEST_AGENT_ID);
        payload.setAgentStatus("ACTIVE");

        TransparencyLogAtiV1.Certificates certs = new TransparencyLogAtiV1.Certificates();
        certs.setServerCertFingerprint(TEST_FINGERPRINT);
        certs.setIdentityCertFingerprint(TEST_FINGERPRINT);
        payload.setCertificates(certs);

        TransparencyLog log = new TransparencyLog();
        log.setStatus("ACTIVE");
        log.setSchemaVersion("ATI-TL-V1");
        log.setParsedPayload(payload);
        return log;
    }
}
