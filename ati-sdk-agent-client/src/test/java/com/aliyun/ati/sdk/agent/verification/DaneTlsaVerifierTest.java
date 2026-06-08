package com.aliyun.ati.sdk.agent.verification;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Collections;
import java.util.List;

import com.aliyun.ati.sdk.crypto.CertUtils;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class DaneTlsaVerifierTest {

    private DaneTlsaVerifier verifier;

    @BeforeEach
    void setUp() {
        verifier = new DaneTlsaVerifier(Duration.ofSeconds(3));
    }

    @Test
    void shouldRejectNullHost() {
        X509Certificate cert = mock(X509Certificate.class);

        assertThatThrownBy(() -> verifier.verify(null, 443, cert))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("host");
    }

    @Test
    void shouldRejectNullCert() {
        assertThatThrownBy(() -> verifier.verify("example.com", 443, null))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("serverCert");
    }

    @Test
    void shouldReturnNotFoundWhenNoTlsaRecord() {
        X509Certificate cert = mock(X509Certificate.class);

        VerificationResult result =
            verifier.verify("nonexistent.invalid", 443, cert);

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.getType())
            .isEqualTo(VerificationResult.Type.DANE);
        assertThat(result.getStatus())
            .isEqualTo(VerificationResult.Status.NOT_FOUND);
    }

    @Test
    void shouldRejectNullTimeout() {
        assertThatThrownBy(() -> new DaneTlsaVerifier(null))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("timeout");
    }

    @Test
    void shouldUseDefaultTimeout() {
        DaneTlsaVerifier defaultVerifier = new DaneTlsaVerifier();
        X509Certificate cert = mock(X509Certificate.class);

        VerificationResult result =
            defaultVerifier.verify("nonexistent.invalid", 443, cert);

        assertThat(result.getType())
            .isEqualTo(VerificationResult.Type.DANE);
    }

    // --- getTlsaExpectations tests ---

    @Test
    void shouldRejectNullHostForGetTlsaExpectations() {
        assertThatThrownBy(
                () -> verifier.getTlsaExpectations(null, 443))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("host");
    }

    @Test
    void shouldReturnEmptyExpectationsWhenNoRecords() {
        List<DaneTlsaVerifier.TlsaExpectation> expectations =
            verifier.getTlsaExpectations(
                "nonexistent.invalid", 443);

        assertThat(expectations).isEmpty();
    }

    // --- postVerify tests ---

    @Test
    void shouldRejectNullCertForPostVerify() {
        assertThatThrownBy(
                () -> verifier.postVerify(null, List.of()))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("serverCert");
    }

    @Test
    void shouldRejectNullExpectationsForPostVerify() {
        X509Certificate cert = mock(X509Certificate.class);
        assertThatThrownBy(
                () -> verifier.postVerify(cert, null))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("expectations");
    }

    @Test
    void shouldReturnNotFoundForPostVerifyWhenEmpty() {
        X509Certificate cert = mock(X509Certificate.class);

        VerificationResult result =
            verifier.postVerify(cert, Collections.emptyList());

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.getStatus())
            .isEqualTo(VerificationResult.Status.NOT_FOUND);
    }

    @Test
    void shouldReturnSuccessOnPostVerifyMatch() throws Exception {
        KeyPairGenerator kpg =
            KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
        byte[] spki = kp.getPublic().getEncoded();
        String spkiHex = CertUtils.sha256Hex(spki);

        X509Certificate cert = mock(X509Certificate.class);
        when(cert.getPublicKey()).thenReturn(kp.getPublic());

        DaneTlsaVerifier.TlsaExpectation exp =
            new DaneTlsaVerifier.TlsaExpectation(
                1, 1, hexToBytes(spkiHex));

        VerificationResult result =
            verifier.postVerify(cert, List.of(exp));

        assertThat(result.isSuccess()).isTrue();
        assertThat(result.getType())
            .isEqualTo(VerificationResult.Type.DANE);
    }

    @Test
    void shouldReturnMismatchOnPostVerifyDifferentKey()
            throws Exception {
        KeyPairGenerator kpg =
            KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        X509Certificate cert = mock(X509Certificate.class);
        when(cert.getPublicKey()).thenReturn(kp.getPublic());

        byte[] wrongData = new byte[32];
        DaneTlsaVerifier.TlsaExpectation exp =
            new DaneTlsaVerifier.TlsaExpectation(1, 1, wrongData);

        VerificationResult result =
            verifier.postVerify(cert, List.of(exp));

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.getStatus())
            .isEqualTo(VerificationResult.Status.MISMATCH);
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
}
