package com.aliyun.ati.sdk.agent.verification;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import com.aliyun.ati.sdk.crypto.CertUtils;
import com.aliyun.ati.sdk.transparency.verification.CachingBadgeVerificationService;
import com.aliyun.ati.sdk.transparency.verification.ServerVerificationResult;
import com.aliyun.ati.sdk.transparency.verification.VerificationStatus;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class BadgeVerifierTest {

    private static final String AGENT_ID = "agent-001";
    private static final byte[] CERT_BYTES = "test-certificate-bytes".getBytes();

    private CachingBadgeVerificationService badgeService;
    private BadgeVerifier verifier;

    @BeforeEach
    void setUp() {
        badgeService = mock(CachingBadgeVerificationService.class);
        verifier = new BadgeVerifier(badgeService);
    }

    @Test
    void shouldReturnSuccessWhenFingerprintMatches()
            throws CertificateEncodingException {
        String expectedFingerprint = CertUtils.sha256Fingerprint(
            mockCertWithEncoded(CERT_BYTES));

        ServerVerificationResult tlResult =
            ServerVerificationResult.verified(expectedFingerprint, AGENT_ID);
        when(badgeService.verifyServer(AGENT_ID)).thenReturn(tlResult);

        X509Certificate serverCert = mockCertWithEncoded(CERT_BYTES);
        VerificationResult result = verifier.verify(AGENT_ID, serverCert);

        assertThat(result.isSuccess()).isTrue();
        assertThat(result.getType())
            .isEqualTo(VerificationResult.Type.BADGE);
        assertThat(result.getStatus())
            .isEqualTo(VerificationResult.Status.SUCCESS);
    }

    @Test
    void shouldReturnMismatchWhenFingerprintDiffers()
            throws CertificateEncodingException {
        String differentFingerprint = "SHA-256:0000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000";

        ServerVerificationResult tlResult =
            ServerVerificationResult.verified(differentFingerprint, AGENT_ID);
        when(badgeService.verifyServer(AGENT_ID)).thenReturn(tlResult);

        X509Certificate serverCert = mockCertWithEncoded(CERT_BYTES);
        VerificationResult result = verifier.verify(AGENT_ID, serverCert);

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.getType())
            .isEqualTo(VerificationResult.Type.BADGE);
        assertThat(result.getStatus())
            .isEqualTo(VerificationResult.Status.MISMATCH);
        assertThat(result.getDetail())
            .contains("fingerprint mismatch");
    }

    @Test
    void shouldReturnErrorWhenBadgeNotVerified() {
        ServerVerificationResult tlResult =
            ServerVerificationResult.failed(
                VerificationStatus.AGENT_REVOKED, AGENT_ID);
        when(badgeService.verifyServer(AGENT_ID)).thenReturn(tlResult);

        X509Certificate serverCert = mock(X509Certificate.class);
        VerificationResult result = verifier.verify(AGENT_ID, serverCert);

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.getType())
            .isEqualTo(VerificationResult.Type.BADGE);
        assertThat(result.getStatus())
            .isEqualTo(VerificationResult.Status.ERROR);
        assertThat(result.getDetail()).contains("AGENT_REVOKED");
    }

    @Test
    void shouldRejectNullBadgeService() {
        assertThatThrownBy(() -> new BadgeVerifier(null))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("badgeService");
    }

    @Test
    void shouldRejectNullAgentId() {
        X509Certificate cert = mock(X509Certificate.class);

        assertThatThrownBy(() -> verifier.verify(null, cert))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("agentId");
    }

    @Test
    void shouldRejectNullServerCert() {
        assertThatThrownBy(() -> verifier.verify(AGENT_ID, null))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("serverCert");
    }

    // --- preVerify tests ---

    @Test
    void shouldReturnTlResultOnPreVerify() {
        ServerVerificationResult expected =
            ServerVerificationResult.verified("SHA-256:abc", AGENT_ID);
        when(badgeService.verifyServer(AGENT_ID)).thenReturn(expected);

        ServerVerificationResult result =
            verifier.preVerify(AGENT_ID);

        assertThat(result).isSameAs(expected);
    }

    @Test
    void shouldRejectNullAgentIdForPreVerify() {
        assertThatThrownBy(() -> verifier.preVerify(null))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("agentId");
    }

    // --- postVerify tests ---

    @Test
    void shouldReturnSuccessOnPostVerifyMatch()
            throws CertificateEncodingException {
        String expectedFingerprint =
            CertUtils.sha256Fingerprint(mockCertWithEncoded(CERT_BYTES));
        ServerVerificationResult tlResult =
            ServerVerificationResult.verified(
                expectedFingerprint, AGENT_ID);

        X509Certificate serverCert = mockCertWithEncoded(CERT_BYTES);
        VerificationResult result =
            verifier.postVerify(serverCert, tlResult);

        assertThat(result.isSuccess()).isTrue();
        assertThat(result.getType())
            .isEqualTo(VerificationResult.Type.BADGE);
    }

    @Test
    void shouldReturnMismatchOnPostVerifyDifferentFingerprint()
            throws CertificateEncodingException {
        String differentFingerprint = "SHA-256:0000000000000000"
            + "0000000000000000000000000000000000000000000000000000000000000000";
        ServerVerificationResult tlResult =
            ServerVerificationResult.verified(
                differentFingerprint, AGENT_ID);

        X509Certificate serverCert = mockCertWithEncoded(CERT_BYTES);
        VerificationResult result =
            verifier.postVerify(serverCert, tlResult);

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.getStatus())
            .isEqualTo(VerificationResult.Status.MISMATCH);
    }

    @Test
    void shouldReturnErrorOnPostVerifyWhenNotVerified() {
        ServerVerificationResult tlResult =
            ServerVerificationResult.failed(
                VerificationStatus.AGENT_REVOKED, AGENT_ID);

        X509Certificate cert = mock(X509Certificate.class);
        VerificationResult result =
            verifier.postVerify(cert, tlResult);

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.getStatus())
            .isEqualTo(VerificationResult.Status.ERROR);
    }

    @Test
    void shouldRejectNullCertForPostVerify() {
        ServerVerificationResult tlResult =
            ServerVerificationResult.verified("SHA-256:abc", AGENT_ID);

        assertThatThrownBy(
                () -> verifier.postVerify(null, tlResult))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("serverCert");
    }

    @Test
    void shouldRejectNullTlResultForPostVerify() {
        X509Certificate cert = mock(X509Certificate.class);

        assertThatThrownBy(
                () -> verifier.postVerify(cert, null))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("tlResult");
    }

    private static X509Certificate mockCertWithEncoded(byte[] encoded)
            throws CertificateEncodingException {
        X509Certificate cert = mock(X509Certificate.class);
        when(cert.getEncoded()).thenReturn(encoded);
        return cert;
    }
}
