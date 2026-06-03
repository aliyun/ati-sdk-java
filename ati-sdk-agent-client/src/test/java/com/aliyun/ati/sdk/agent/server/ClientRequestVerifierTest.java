package com.aliyun.ati.sdk.agent.server;

import java.security.cert.X509Certificate;

import com.aliyun.ati.sdk.crypto.CertUtils;
import com.aliyun.ati.sdk.transparency.verification.CachingBadgeVerificationService;
import com.aliyun.ati.sdk.transparency.verification.ClientVerificationResult;
import com.aliyun.ati.sdk.transparency.verification.VerificationStatus;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ClientRequestVerifierTest {

    private CachingBadgeVerificationService badgeService;
    private ClientRequestVerifier verifier;

    @BeforeEach
    void setUp() {
        badgeService = mock(CachingBadgeVerificationService.class);
        verifier = new ClientRequestVerifier(badgeService);
    }

    @Test
    void shouldVerifyMatchingFingerprint() throws Exception {
        X509Certificate cert = mock(X509Certificate.class);
        when(cert.getEncoded()).thenReturn("test-cert-data".getBytes());
        String fingerprint = CertUtils.sha256Fingerprint(cert);

        ClientVerificationResult tlResult = ClientVerificationResult.verified(
            fingerprint, "agent.example.com", "agent-1");
        when(badgeService.verifyClient("agent-1")).thenReturn(tlResult);

        ClientVerificationResult result = verifier.verify(cert, "agent-1");

        assertThat(result.getStatus()).isEqualTo(VerificationStatus.VERIFIED);
    }

    @Test
    void shouldReturnMismatchWhenFingerprintsDiffer() throws Exception {
        X509Certificate cert = mock(X509Certificate.class);
        when(cert.getEncoded()).thenReturn("actual-cert-data".getBytes());

        ClientVerificationResult tlResult = ClientVerificationResult.verified(
            "SHA-256:0000000000000000000000000000000000000000000000000000000000000000",
            "agent.example.com", "agent-1");
        when(badgeService.verifyClient("agent-1")).thenReturn(tlResult);

        ClientVerificationResult result = verifier.verify(cert, "agent-1");

        assertThat(result.getStatus()).isEqualTo(VerificationStatus.FINGERPRINT_MISMATCH);
    }

    @Test
    void shouldReturnTlResultWhenNotVerified() {
        X509Certificate cert = mock(X509Certificate.class);
        ClientVerificationResult tlResult = ClientVerificationResult.failed(
            VerificationStatus.AGENT_REVOKED, "agent-1");
        when(badgeService.verifyClient("agent-1")).thenReturn(tlResult);

        ClientVerificationResult result = verifier.verify(cert, "agent-1");

        assertThat(result.getStatus()).isEqualTo(VerificationStatus.AGENT_REVOKED);
    }

    @Test
    void shouldRejectNullCert() {
        assertThatThrownBy(() -> verifier.verify(null, "agent-1"))
            .isInstanceOf(NullPointerException.class);
    }

    @Test
    void shouldRejectNullAgentId() {
        X509Certificate cert = mock(X509Certificate.class);
        assertThatThrownBy(() -> verifier.verify(cert, null))
            .isInstanceOf(NullPointerException.class);
    }
}
