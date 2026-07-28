package com.aliyun.ati.sdk.agent.verification;

import com.aliyun.ati.sdk.crypto.CertificateUtils;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.concurrent.Executor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.anyInt;
import static org.mockito.Mockito.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link DaneVerifier}.
 * Covers test scenarios 7.1-7.5 from test-cases.md (DANE/TLSA Verification).
 */
class DaneVerifierTest {

    private static final String TEST_HOSTNAME = "agent.example.com";
    private static final int TEST_PORT = 443;

    @Mock
    private DaneTlsaVerifier tlsaVerifier;

    private DaneVerifier daneVerifier;

    // Use synchronous executor for testing
    private final Executor syncExecutor = Runnable::run;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        daneVerifier = new DaneVerifier(tlsaVerifier, syncExecutor);
    }

    // ==================== 7.1 DNSSEC Validated, TLSA Matches ====================

    @Test
    @DisplayName("7.1 Should pass when DNSSEC validated and TLSA matches")
    void shouldPassWhenDnssecValidatedAndTlsaMatches() throws Exception {
        // Given - create a test certificate
        X509Certificate cert = createTestCertificate("CN=" + TEST_HOSTNAME);
        String actualFingerprint = CertificateUtils.computeSha256Fingerprint(cert);
        byte[] fingerprintBytes = hexToBytes(actualFingerprint.replace("SHA256:", ""));

        // Mock getTlsaExpectations to return expectation with matching fingerprint
        // selector=0 (full cert), matchingType=1 (SHA256)
        DaneTlsaVerifier.TlsaExpectation expectation = new DaneTlsaVerifier.TlsaExpectation(
            0, 1, fingerprintBytes);
        when(tlsaVerifier.getTlsaExpectations(TEST_HOSTNAME, TEST_PORT))
            .thenReturn(List.of(expectation));

        // When - pre-verify (single DNS call, no TLS connection)
        DaneVerifier.PreVerifyResult preResult =
            daneVerifier.preVerify(TEST_HOSTNAME, TEST_PORT).join();

        // Then - should have expectations
        assertThat(preResult.expectations()).hasSize(1);
        assertThat(preResult.isDnsError()).isFalse();

        // Verify only getTlsaExpectations was called (not hasTlsaRecord or verifyTlsa)
        verify(tlsaVerifier).getTlsaExpectations(TEST_HOSTNAME, TEST_PORT);
        verify(tlsaVerifier, never()).hasTlsaRecord(anyString(), anyInt());
        verify(tlsaVerifier, never()).verifyTlsa(anyString(), anyInt());

        // When - post-verify with matching cert
        VerificationResult result = daneVerifier.postVerify(TEST_HOSTNAME, cert, preResult.expectations());

        // Then - should succeed
        assertThat(result.status()).isEqualTo(VerificationResult.Status.SUCCESS);
        assertThat(result.type()).isEqualTo(VerificationResult.VerificationType.DANE);
    }

    // ==================== 7.2 DNSSEC Validated, TLSA Mismatch ====================

    @Test
    @DisplayName("7.2 Should reject when DNSSEC validated but TLSA mismatches")
    void shouldRejectWhenDnssecValidatedButTlsaMismatches() throws Exception {
        // Given - create a test certificate
        X509Certificate cert = createTestCertificate("CN=" + TEST_HOSTNAME);
        byte[] differentFingerprint = new byte[32]; // Random - won't match
        new SecureRandom().nextBytes(differentFingerprint);

        // Mock getTlsaExpectations to return expectation with DIFFERENT fingerprint
        DaneTlsaVerifier.TlsaExpectation expectation = new DaneTlsaVerifier.TlsaExpectation(
            0, 1, differentFingerprint);
        when(tlsaVerifier.getTlsaExpectations(TEST_HOSTNAME, TEST_PORT))
            .thenReturn(List.of(expectation));

        // When - pre-verify (single DNS call, no TLS connection)
        DaneVerifier.PreVerifyResult preResult =
            daneVerifier.preVerify(TEST_HOSTNAME, TEST_PORT).join();

        // Then - should have expectations
        assertThat(preResult.expectations()).hasSize(1);

        // When - post-verify with mismatched cert
        VerificationResult result = daneVerifier.postVerify(TEST_HOSTNAME, cert, preResult.expectations());

        // Then - should fail with mismatch
        assertThat(result.status()).isEqualTo(VerificationResult.Status.MISMATCH);
        assertThat(result.type()).isEqualTo(VerificationResult.VerificationType.DANE);
    }

    // ==================== 7.3 No DNSSEC Present ====================

    @Test
    @DisplayName("7.3 Should skip DANE when no DNSSEC present")
    void shouldSkipDaneWhenNoDnssecPresent() throws Exception {
        // Given - create a test certificate
        X509Certificate cert = createTestCertificate("CN=" + TEST_HOSTNAME);

        // Mock getTlsaExpectations to return empty list (no TLSA record)
        when(tlsaVerifier.getTlsaExpectations(TEST_HOSTNAME, TEST_PORT))
            .thenReturn(List.of());

        // When - pre-verify (single DNS call, no TLS connection)
        DaneVerifier.PreVerifyResult preResult =
            daneVerifier.preVerify(TEST_HOSTNAME, TEST_PORT).join();

        // Then - should have no expectations
        assertThat(preResult.expectations()).isEmpty();
        assertThat(preResult.isDnsError()).isFalse();

        // When - post-verify with empty expectations
        VerificationResult result = daneVerifier.postVerify(TEST_HOSTNAME, cert, preResult.expectations());

        // Then - should return NOT_FOUND (DANE skipped, not an error)
        assertThat(result.status()).isEqualTo(VerificationResult.Status.NOT_FOUND);
        assertThat(result.type()).isEqualTo(VerificationResult.VerificationType.DANE);
        assertThat(result.reason()).contains("No TLSA record");
    }

    // ==================== 7.4 DNSSEC Validation Failure ====================

    @Test
    @DisplayName("7.4 Should return DNS error when DNSSEC validation fails")
    void shouldRejectWhenDnssecValidationFails() throws Exception {
        // Given - create a test certificate
        X509Certificate cert = createTestCertificate("CN=" + TEST_HOSTNAME);

        // Mock getTlsaExpectations to throw exception (DNSSEC validation failed)
        when(tlsaVerifier.getTlsaExpectations(TEST_HOSTNAME, TEST_PORT))
            .thenThrow(new RuntimeException("DNSSEC validation failed"));

        // When - pre-verify (single DNS call that fails)
        DaneVerifier.PreVerifyResult preResult =
            daneVerifier.preVerify(TEST_HOSTNAME, TEST_PORT).join();

        // Then - should indicate DNS error
        assertThat(preResult.expectations()).isEmpty();
        assertThat(preResult.isDnsError()).isTrue();
        assertThat(preResult.errorMessage()).contains("DNSSEC validation failed");

        // When - post-verify with empty expectations
        VerificationResult result = daneVerifier.postVerify(TEST_HOSTNAME, cert, preResult.expectations());

        // Then - should return NOT_FOUND (treat as no valid DANE for postVerify)
        // Note: The caller (DefaultConnectionVerifier) should check isDnsError() first
        assertThat(result.status()).isEqualTo(VerificationResult.Status.NOT_FOUND);
    }

    // ==================== 7.5 Multiple TLSA Records (Renewal) ====================

    @Test
    @DisplayName("7.5 Should pass when first TLSA record matches during renewal")
    void shouldPassWhenFirstTlsaRecordMatchesDuringRenewal() throws Exception {
        // Given - create a test certificate (the currently active cert)
        X509Certificate activeCert = createTestCertificate("CN=" + TEST_HOSTNAME);
        String activeFingerprint = CertificateUtils.computeSha256Fingerprint(activeCert);
        byte[] activeFingerprintBytes = hexToBytes(activeFingerprint.replace("SHA256:", ""));

        // Also create a "next" fingerprint for upcoming rotation
        byte[] nextFingerprintBytes = new byte[32];
        new SecureRandom().nextBytes(nextFingerprintBytes);

        // Mock getTlsaExpectations to return multiple expectations
        // Active cert's record is first (current), next cert's record is second (pre-published for rotation)
        DaneTlsaVerifier.TlsaExpectation activeExpectation = new DaneTlsaVerifier.TlsaExpectation(
            0, 1, activeFingerprintBytes);
        DaneTlsaVerifier.TlsaExpectation nextExpectation = new DaneTlsaVerifier.TlsaExpectation(
            0, 1, nextFingerprintBytes);
        when(tlsaVerifier.getTlsaExpectations(TEST_HOSTNAME, TEST_PORT))
            .thenReturn(List.of(activeExpectation, nextExpectation));

        // When - pre-verify (single DNS call, returns ALL expectations)
        DaneVerifier.PreVerifyResult preResult =
            daneVerifier.preVerify(TEST_HOSTNAME, TEST_PORT).join();

        // Then - should have both expectations
        assertThat(preResult.expectations()).hasSize(2);

        // When - post-verify with active cert (matches first expectation)
        VerificationResult result = daneVerifier.postVerify(TEST_HOSTNAME, activeCert, preResult.expectations());

        // Then - should succeed since active cert matches first TLSA record
        assertThat(result.status()).isEqualTo(VerificationResult.Status.SUCCESS);
        assertThat(result.type()).isEqualTo(VerificationResult.VerificationType.DANE);
    }

    @Test
    @DisplayName("7.5b Should pass when ANY TLSA record matches (certificate rotation)")
    void shouldPassWhenAnyTlsaRecordMatchesDuringRotation() throws Exception {
        // This test verifies that during certificate rotation, the server can use
        // the NEW certificate even if the old cert's TLSA record is listed first.
        // postVerify tries ALL expectations and succeeds if ANY matches.

        // Given - certificate that matches second record (not first)
        X509Certificate rotatedCert = createTestCertificate("CN=" + TEST_HOSTNAME);
        String rotatedFingerprint = CertificateUtils.computeSha256Fingerprint(rotatedCert);
        byte[] rotatedFingerprintBytes = hexToBytes(rotatedFingerprint.replace("SHA256:", ""));

        byte[] oldFingerprintBytes = new byte[32];
        new SecureRandom().nextBytes(oldFingerprintBytes);

        // Old record first, rotated cert's record second
        DaneTlsaVerifier.TlsaExpectation oldExpectation = new DaneTlsaVerifier.TlsaExpectation(
            0, 1, oldFingerprintBytes);
        DaneTlsaVerifier.TlsaExpectation rotatedExpectation = new DaneTlsaVerifier.TlsaExpectation(
            0, 1, rotatedFingerprintBytes);
        when(tlsaVerifier.getTlsaExpectations(TEST_HOSTNAME, TEST_PORT))
            .thenReturn(List.of(oldExpectation, rotatedExpectation));

        // When - pre-verify returns ALL expectations
        DaneVerifier.PreVerifyResult preResult =
            daneVerifier.preVerify(TEST_HOSTNAME, TEST_PORT).join();

        // Then - should have both expectations
        assertThat(preResult.expectations()).hasSize(2);

        // When - post-verify with rotated cert (matches SECOND expectation)
        VerificationResult result = daneVerifier.postVerify(TEST_HOSTNAME, rotatedCert, preResult.expectations());

        // Then - should SUCCEED because postVerify tries ALL expectations
        assertThat(result.status()).isEqualTo(VerificationResult.Status.SUCCESS);
        assertThat(result.type()).isEqualTo(VerificationResult.VerificationType.DANE);
    }

    @Test
    @DisplayName("7.5c Should handle pre-verify exception gracefully")
    void shouldHandlePreVerifyExceptionGracefully() throws Exception {
        // Given - TLSA lookup throws exception
        when(tlsaVerifier.getTlsaExpectations(TEST_HOSTNAME, TEST_PORT))
            .thenThrow(new RuntimeException("DNS query timeout"));

        // When - pre-verify
        DaneVerifier.PreVerifyResult preResult =
            daneVerifier.preVerify(TEST_HOSTNAME, TEST_PORT).join();

        // Then - should return DNS error with empty expectations
        assertThat(preResult.expectations()).isEmpty();
        assertThat(preResult.isDnsError()).isTrue();
        assertThat(preResult.errorMessage()).contains("DNS query timeout");
    }

    // ==================== PreVerifyResult Tests ====================

    @Test
    @DisplayName("PreVerifyResult.success creates successful result")
    void preVerifyResultSuccessCreatesSuccessfulResult() {
        byte[] data = new byte[32];
        List<DaneTlsaVerifier.TlsaExpectation> expectations = List.of(
            new DaneTlsaVerifier.TlsaExpectation(0, 1, data));

        DaneVerifier.PreVerifyResult result = DaneVerifier.PreVerifyResult.success(expectations);

        assertThat(result.expectations()).hasSize(1);
        assertThat(result.isDnsError()).isFalse();
        assertThat(result.errorMessage()).isNull();
        assertThat(result.hasExpectations()).isTrue();
    }

    @Test
    @DisplayName("PreVerifyResult.success with null creates empty expectations")
    void preVerifyResultSuccessWithNullCreatesEmptyExpectations() {
        DaneVerifier.PreVerifyResult result = DaneVerifier.PreVerifyResult.success(null);

        assertThat(result.expectations()).isEmpty();
        assertThat(result.isDnsError()).isFalse();
        assertThat(result.hasExpectations()).isFalse();
    }

    @Test
    @DisplayName("PreVerifyResult.dnsError creates error result")
    void preVerifyResultDnsErrorCreatesErrorResult() {
        DaneVerifier.PreVerifyResult result = DaneVerifier.PreVerifyResult.dnsError("Connection refused");

        assertThat(result.expectations()).isEmpty();
        assertThat(result.isDnsError()).isTrue();
        assertThat(result.errorMessage()).isEqualTo("Connection refused");
        assertThat(result.hasExpectations()).isFalse();
    }

    @Test
    @DisplayName("PreVerifyResult.toString for success")
    void preVerifyResultToStringForSuccess() {
        byte[] data = new byte[32];
        List<DaneTlsaVerifier.TlsaExpectation> expectations = List.of(
            new DaneTlsaVerifier.TlsaExpectation(0, 1, data));

        DaneVerifier.PreVerifyResult result = DaneVerifier.PreVerifyResult.success(expectations);

        assertThat(result.toString()).contains("expectations=1");
    }

    @Test
    @DisplayName("PreVerifyResult.toString for DNS error")
    void preVerifyResultToStringForDnsError() {
        DaneVerifier.PreVerifyResult result = DaneVerifier.PreVerifyResult.dnsError("Timeout");

        assertThat(result.toString()).contains("dnsError=Timeout");
    }

    @Test
    @DisplayName("preVerifyExpectations returns expectations list")
    void preVerifyExpectationsReturnsExpectationsList() throws Exception {
        byte[] data = new byte[32];
        List<DaneTlsaVerifier.TlsaExpectation> expectations = List.of(
            new DaneTlsaVerifier.TlsaExpectation(0, 1, data));
        when(tlsaVerifier.getTlsaExpectations(TEST_HOSTNAME, TEST_PORT))
            .thenReturn(expectations);

        List<DaneTlsaVerifier.TlsaExpectation> result =
            daneVerifier.preVerifyExpectations(TEST_HOSTNAME, TEST_PORT).join();

        assertThat(result).hasSize(1);
    }

    // ==================== Helper Methods ====================

    /**
     * Creates a self-signed test certificate with the given subject DN.
     */
    private X509Certificate createTestCertificate(String subjectDn) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048, new SecureRandom());
        KeyPair keyPair = keyGen.generateKeyPair();

        X500Name issuer = new X500Name(subjectDn);
        X500Name subject = new X500Name(subjectDn);
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date(System.currentTimeMillis() - 24 * 60 * 60 * 1000);
        Date notAfter = new Date(System.currentTimeMillis() + 365 * 24 * 60 * 60 * 1000L);

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
            issuer, serial, notBefore, notAfter, subject, keyPair.getPublic());

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithRSA")
            .build(keyPair.getPrivate());

        return new JcaX509CertificateConverter()
            .getCertificate(certBuilder.build(signer));
    }

    /**
     * Converts hex string to byte array.
     */
    private byte[] hexToBytes(String hex) {
        if (hex == null || hex.isEmpty()) {
            return new byte[0];
        }
        // Remove colons if present
        hex = hex.replace(":", "").replace(" ", "");
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

}
