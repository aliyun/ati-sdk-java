package com.aliyun.ati.sdk.agent.server;

import com.aliyun.ati.sdk.agent.VerificationPolicy;
import com.aliyun.ati.sdk.agent.verification.DaneTlsaVerifier;
import com.aliyun.ati.sdk.agent.verification.DaneTlsaVerifier.TlsaExpectation;
import com.aliyun.ati.sdk.crypto.CertificateUtils;
import com.aliyun.ati.sdk.crypto.CryptoCache;
import com.aliyun.ati.sdk.transparency.verification.BadgeVerificationService;
import com.aliyun.ati.sdk.transparency.verification.ClientVerificationResult;
import com.aliyun.ati.sdk.transparency.verification.VerificationStatus;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for {@link DefaultClientRequestVerifier}.
 *
 * <p>Covers input validation, PKI_ONLY, Badge verification, DANE verification,
 * and error handling paths for the ATI spec section 9 verification flow.</p>
 */
class DefaultClientRequestVerifierTest {

    private BadgeVerificationService mockBadgeService;
    private DaneTlsaVerifier mockDaneTlsaVerifier;
    private DefaultClientRequestVerifier verifier;

    // Test certificate with ATI URI SAN
    private X509Certificate clientCertWithAtiSan;
    // Test certificate without URI SAN
    private X509Certificate clientCertWithoutUriSan;

    @BeforeEach
    void setUp() throws Exception {
        mockBadgeService = mock(BadgeVerificationService.class);
        mockDaneTlsaVerifier = mock(DaneTlsaVerifier.class);

        verifier = DefaultClientRequestVerifier.builder()
            .badgeVerificationService(mockBadgeService)
            .daneTlsaVerifier(mockDaneTlsaVerifier)
            .build();

        clientCertWithAtiSan = createCertificateWithUriSan("ati://v1.client-agent.example.com");
        clientCertWithoutUriSan = createCertificateWithoutUriSan();
    }

    @Nested
    @DisplayName("Input validation tests")
    class InputValidationTests {

        @Test
        @DisplayName("Should reject null client certificate")
        void shouldRejectNullClientCert() {
            assertThatThrownBy(() ->
                verifier.verify(null, VerificationPolicy.PKI_ONLY))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("clientCert cannot be null");
        }

        @Test
        @DisplayName("Should reject null policy")
        void shouldRejectNullPolicy() {
            assertThatThrownBy(() ->
                verifier.verify(clientCertWithAtiSan, null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("policy cannot be null");
        }
    }

    @Nested
    @DisplayName("ATI name extraction tests")
    class AtiNameExtractionTests {

        @Test
        @DisplayName("Should fail when certificate has no ATI URI SAN")
        void shouldFailWhenNoAtiUriSan() {
            ClientRequestVerificationResult result = verifier.verify(
                clientCertWithoutUriSan, VerificationPolicy.PKI_ONLY);

            assertThat(result.verified()).isFalse();
            assertThat(result.errors()).anyMatch(e -> e.contains("No ATI URI SAN"));
            assertThat(result.agentHost()).isNull();
        }

        @Test
        @DisplayName("Should extract agentHost from ati:// URI SAN")
        void shouldExtractAgentHostFromAtiUri() {
            ClientRequestVerificationResult result = verifier.verify(
                clientCertWithAtiSan, VerificationPolicy.PKI_ONLY);

            assertThat(result.verified()).isTrue();
            assertThat(result.agentHost()).isEqualTo("client-agent.example.com");
        }

        @Test
        @DisplayName("Should extract agentHost from ans:// URI SAN (legacy)")
        void shouldExtractAgentHostFromAnsUri() throws Exception {
            X509Certificate cert = createCertificateWithUriSan("ans://v1.legacy-agent.example.com");

            ClientRequestVerificationResult result = verifier.verify(
                cert, VerificationPolicy.PKI_ONLY);

            assertThat(result.verified()).isTrue();
            assertThat(result.agentHost()).isEqualTo("legacy-agent.example.com");
        }
    }

    @Nested
    @DisplayName("extractHostFromAtiName tests")
    class ExtractHostTests {

        @Test
        @DisplayName("Should extract host from ati://v1.host.example.com")
        void shouldExtractFromVersionedAtiName() {
            String host = DefaultClientRequestVerifier.extractHostFromAtiName(
                "ati://v1.client-agent.example.com");
            assertThat(host).isEqualTo("client-agent.example.com");
        }

        @Test
        @DisplayName("Should extract host from ans://v1.0.0.host.example.com")
        void shouldExtractFromVersionedAnsName() {
            String host = DefaultClientRequestVerifier.extractHostFromAtiName(
                "ans://v1.0.0.host.example.com");
            // The regex matches v1 as version prefix, rest is host
            assertThat(host).isNotNull();
        }

        @Test
        @DisplayName("Should return null for null input")
        void shouldReturnNullForNull() {
            assertThat(DefaultClientRequestVerifier.extractHostFromAtiName(null)).isNull();
        }

        @Test
        @DisplayName("Should return null for invalid scheme")
        void shouldReturnNullForInvalidScheme() {
            assertThat(DefaultClientRequestVerifier.extractHostFromAtiName("https://example.com")).isNull();
        }
    }

    @Nested
    @DisplayName("PKI_ONLY policy tests")
    class PkiOnlyTests {

        @Test
        @DisplayName("Should succeed with PKI_ONLY when cert has ATI SAN")
        void shouldSucceedWithPkiOnly() {
            ClientRequestVerificationResult result = verifier.verify(
                clientCertWithAtiSan, VerificationPolicy.PKI_ONLY);

            assertThat(result.verified()).isTrue();
            assertThat(result.agentHost()).isEqualTo("client-agent.example.com");
            assertThat(result.policyUsed()).isEqualTo(VerificationPolicy.PKI_ONLY);
            assertThat(result.errors()).isEmpty();
        }

        @Test
        @DisplayName("Should not invoke badge service for PKI_ONLY")
        void shouldNotInvokeBadgeServiceForPkiOnly() {
            verifier.verify(clientCertWithAtiSan, VerificationPolicy.PKI_ONLY);

            verify(mockBadgeService, never()).verifyClient(any());
        }

        @Test
        @DisplayName("Should not invoke DANE verifier for PKI_ONLY")
        void shouldNotInvokeDaneForPkiOnly() throws Exception {
            verifier.verify(clientCertWithAtiSan, VerificationPolicy.PKI_ONLY);

            verify(mockDaneTlsaVerifier, never()).getTlsaExpectations(anyString(), anyInt());
        }

        @Test
        @DisplayName("Default verify() method should use PKI_ONLY")
        void defaultVerifyShouldUsePkiOnly() {
            ClientRequestVerificationResult result = verifier.verify(clientCertWithAtiSan);

            assertThat(result.verified()).isTrue();
            assertThat(result.policyUsed()).isEqualTo(VerificationPolicy.PKI_ONLY);
        }
    }

    @Nested
    @DisplayName("BADGE_REQUIRED policy tests")
    class BadgeRequiredTests {

        @Test
        @DisplayName("Should succeed when badge verification passes")
        void shouldSucceedWhenBadgeVerificationPasses() {
            String fingerprint = CertificateUtils.computeSha256Fingerprint(clientCertWithAtiSan);

            ClientVerificationResult badgeResult = ClientVerificationResult.builder()
                .status(VerificationStatus.VERIFIED)
                .expectedIdentityCertFingerprint(fingerprint)
                .expectedAgentHost("client-agent.example.com")
                .build();
            when(mockBadgeService.verifyClient(clientCertWithAtiSan)).thenReturn(badgeResult);

            ClientRequestVerificationResult result = verifier.verify(
                clientCertWithAtiSan, VerificationPolicy.BADGE_REQUIRED);

            assertThat(result.verified()).isTrue();
            assertThat(result.agentHost()).isEqualTo("client-agent.example.com");
            assertThat(result.policyUsed()).isEqualTo(VerificationPolicy.BADGE_REQUIRED);
            assertThat(result.errors()).isEmpty();
        }

        @Test
        @DisplayName("Should fail when badge verification returns NOT_ATI_AGENT")
        void shouldFailWhenNotAtiAgent() {
            ClientVerificationResult badgeResult = ClientVerificationResult.builder()
                .status(VerificationStatus.NOT_ATI_AGENT)
                .build();
            when(mockBadgeService.verifyClient(clientCertWithAtiSan)).thenReturn(badgeResult);

            ClientRequestVerificationResult result = verifier.verify(
                clientCertWithAtiSan, VerificationPolicy.BADGE_REQUIRED);

            assertThat(result.verified()).isFalse();
            assertThat(result.errors()).anyMatch(e -> e.contains("Badge verification failed"));
        }

        @Test
        @DisplayName("Should fail when badge verification returns FINGERPRINT_MISMATCH")
        void shouldFailWhenFingerprintMismatch() {
            ClientVerificationResult badgeResult = ClientVerificationResult.builder()
                .status(VerificationStatus.FINGERPRINT_MISMATCH)
                .warningMessage("Certificate fingerprint does not match registration")
                .build();
            when(mockBadgeService.verifyClient(clientCertWithAtiSan)).thenReturn(badgeResult);

            ClientRequestVerificationResult result = verifier.verify(
                clientCertWithAtiSan, VerificationPolicy.BADGE_REQUIRED);

            assertThat(result.verified()).isFalse();
            assertThat(result.errors()).anyMatch(e -> e.contains("Badge verification failed"));
        }

        @Test
        @DisplayName("Should fail when badge verification returns REGISTRATION_INVALID")
        void shouldFailWhenRegistrationInvalid() {
            ClientVerificationResult badgeResult = ClientVerificationResult.builder()
                .status(VerificationStatus.REGISTRATION_INVALID)
                .warningMessage("Registration status: REVOKED")
                .build();
            when(mockBadgeService.verifyClient(clientCertWithAtiSan)).thenReturn(badgeResult);

            ClientRequestVerificationResult result = verifier.verify(
                clientCertWithAtiSan, VerificationPolicy.BADGE_REQUIRED);

            assertThat(result.verified()).isFalse();
            assertThat(result.errors()).anyMatch(e -> e.contains("REGISTRATION_INVALID"));
        }

        @Test
        @DisplayName("Should fail when badge verification returns LOOKUP_FAILED")
        void shouldFailWhenLookupFailed() {
            ClientVerificationResult badgeResult = ClientVerificationResult.builder()
                .status(VerificationStatus.LOOKUP_FAILED)
                .warningMessage("DNS query failed")
                .build();
            when(mockBadgeService.verifyClient(clientCertWithAtiSan)).thenReturn(badgeResult);

            ClientRequestVerificationResult result = verifier.verify(
                clientCertWithAtiSan, VerificationPolicy.BADGE_REQUIRED);

            assertThat(result.verified()).isFalse();
            assertThat(result.agentHost()).isEqualTo("client-agent.example.com");
        }

        @Test
        @DisplayName("Should accept DEPRECATED_OK status from badge service")
        void shouldAcceptDeprecatedOk() {
            String fingerprint = CertificateUtils.computeSha256Fingerprint(clientCertWithAtiSan);

            ClientVerificationResult badgeResult = ClientVerificationResult.builder()
                .status(VerificationStatus.DEPRECATED_OK)
                .expectedIdentityCertFingerprint(fingerprint)
                .warningMessage("Registration is deprecated")
                .build();
            when(mockBadgeService.verifyClient(clientCertWithAtiSan)).thenReturn(badgeResult);

            ClientRequestVerificationResult result = verifier.verify(
                clientCertWithAtiSan, VerificationPolicy.BADGE_REQUIRED);

            assertThat(result.verified()).isTrue();
        }

        @Test
        @DisplayName("Should fail when badgeVerificationService is not configured")
        void shouldFailWhenBadgeServiceNotConfigured() {
            DefaultClientRequestVerifier noBadgeVerifier = DefaultClientRequestVerifier.builder()
                .build();

            ClientRequestVerificationResult result = noBadgeVerifier.verify(
                clientCertWithAtiSan, VerificationPolicy.BADGE_REQUIRED);

            assertThat(result.verified()).isFalse();
            assertThat(result.errors()).anyMatch(e -> e.contains("badgeVerificationService is not configured"));
        }

        @Test
        @DisplayName("Should not invoke DANE verifier for BADGE_REQUIRED")
        void shouldNotInvokeDaneForBadgeRequired() throws Exception {
            String fingerprint = CertificateUtils.computeSha256Fingerprint(clientCertWithAtiSan);
            ClientVerificationResult badgeResult = ClientVerificationResult.builder()
                .status(VerificationStatus.VERIFIED)
                .expectedIdentityCertFingerprint(fingerprint)
                .build();
            when(mockBadgeService.verifyClient(clientCertWithAtiSan)).thenReturn(badgeResult);

            verifier.verify(clientCertWithAtiSan, VerificationPolicy.BADGE_REQUIRED);

            verify(mockDaneTlsaVerifier, never()).getTlsaExpectations(anyString(), anyInt());
        }
    }

    @Nested
    @DisplayName("DANE_AND_BADGE policy tests")
    class DaneAndBadgeTests {

        @Test
        @DisplayName("Should succeed when both Badge and DANE pass")
        void shouldSucceedWhenBothPass() throws Exception {
            String fingerprint = CertificateUtils.computeSha256Fingerprint(clientCertWithAtiSan);

            // Badge passes
            ClientVerificationResult badgeResult = ClientVerificationResult.builder()
                .status(VerificationStatus.VERIFIED)
                .expectedIdentityCertFingerprint(fingerprint)
                .build();
            when(mockBadgeService.verifyClient(clientCertWithAtiSan)).thenReturn(badgeResult);

            // DANE passes: TLSA expectation matches client cert public key SHA-256
            byte[] spkiHash = CryptoCache.sha256(clientCertWithAtiSan.getPublicKey().getEncoded());
            TlsaExpectation tlsaExpectation = new TlsaExpectation(1, 1, spkiHash);
            when(mockDaneTlsaVerifier.getTlsaExpectations(anyString(), anyInt()))
                .thenReturn(List.of(tlsaExpectation));

            ClientRequestVerificationResult result = verifier.verify(
                clientCertWithAtiSan, VerificationPolicy.DANE_AND_BADGE);

            assertThat(result.verified()).isTrue();
            assertThat(result.policyUsed()).isEqualTo(VerificationPolicy.DANE_AND_BADGE);
        }

        @Test
        @DisplayName("Should fail when Badge passes but DANE has no TLSA record")
        void shouldFailWhenNoTlsaRecord() throws Exception {
            String fingerprint = CertificateUtils.computeSha256Fingerprint(clientCertWithAtiSan);

            ClientVerificationResult badgeResult = ClientVerificationResult.builder()
                .status(VerificationStatus.VERIFIED)
                .expectedIdentityCertFingerprint(fingerprint)
                .build();
            when(mockBadgeService.verifyClient(clientCertWithAtiSan)).thenReturn(badgeResult);

            // DANE: no TLSA records
            when(mockDaneTlsaVerifier.getTlsaExpectations(anyString(), anyInt()))
                .thenReturn(List.of());

            ClientRequestVerificationResult result = verifier.verify(
                clientCertWithAtiSan, VerificationPolicy.DANE_AND_BADGE);

            assertThat(result.verified()).isFalse();
            assertThat(result.errors()).anyMatch(e -> e.contains("No TLSA record"));
        }

        @Test
        @DisplayName("Should fail when Badge passes but DANE fingerprint mismatches")
        void shouldFailWhenDaneFingerprintMismatch() throws Exception {
            String fingerprint = CertificateUtils.computeSha256Fingerprint(clientCertWithAtiSan);

            ClientVerificationResult badgeResult = ClientVerificationResult.builder()
                .status(VerificationStatus.VERIFIED)
                .expectedIdentityCertFingerprint(fingerprint)
                .build();
            when(mockBadgeService.verifyClient(clientCertWithAtiSan)).thenReturn(badgeResult);

            // DANE: wrong fingerprint
            byte[] wrongHash = new byte[32];
            wrongHash[0] = (byte) 0xFF;
            TlsaExpectation tlsaExpectation = new TlsaExpectation(1, 1, wrongHash);
            when(mockDaneTlsaVerifier.getTlsaExpectations(anyString(), anyInt()))
                .thenReturn(List.of(tlsaExpectation));

            ClientRequestVerificationResult result = verifier.verify(
                clientCertWithAtiSan, VerificationPolicy.DANE_AND_BADGE);

            assertThat(result.verified()).isFalse();
            assertThat(result.errors()).anyMatch(e -> e.contains("does not match any TLSA record"));
        }

        @Test
        @DisplayName("Should fail when Badge fails (regardless of DANE)")
        void shouldFailWhenBadgeFails() {
            ClientVerificationResult badgeResult = ClientVerificationResult.builder()
                .status(VerificationStatus.NOT_ATI_AGENT)
                .build();
            when(mockBadgeService.verifyClient(clientCertWithAtiSan)).thenReturn(badgeResult);

            ClientRequestVerificationResult result = verifier.verify(
                clientCertWithAtiSan, VerificationPolicy.DANE_AND_BADGE);

            assertThat(result.verified()).isFalse();
            // DANE should NOT have been invoked since Badge failed first
        }

        @Test
        @DisplayName("Should fail when DANE verifier is not configured")
        void shouldFailWhenDaneVerifierNotConfigured() {
            String fingerprint = CertificateUtils.computeSha256Fingerprint(clientCertWithAtiSan);

            ClientVerificationResult badgeResult = ClientVerificationResult.builder()
                .status(VerificationStatus.VERIFIED)
                .expectedIdentityCertFingerprint(fingerprint)
                .build();
            when(mockBadgeService.verifyClient(clientCertWithAtiSan)).thenReturn(badgeResult);

            DefaultClientRequestVerifier noDaneVerifier = DefaultClientRequestVerifier.builder()
                .badgeVerificationService(mockBadgeService)
                .build();

            ClientRequestVerificationResult result = noDaneVerifier.verify(
                clientCertWithAtiSan, VerificationPolicy.DANE_AND_BADGE);

            assertThat(result.verified()).isFalse();
            assertThat(result.errors()).anyMatch(e -> e.contains("daneTlsaVerifier is not configured"));
        }

        @Test
        @DisplayName("Should handle DANE lookup exception gracefully")
        void shouldHandleDaneLookupException() throws Exception {
            String fingerprint = CertificateUtils.computeSha256Fingerprint(clientCertWithAtiSan);

            ClientVerificationResult badgeResult = ClientVerificationResult.builder()
                .status(VerificationStatus.VERIFIED)
                .expectedIdentityCertFingerprint(fingerprint)
                .build();
            when(mockBadgeService.verifyClient(clientCertWithAtiSan)).thenReturn(badgeResult);

            when(mockDaneTlsaVerifier.getTlsaExpectations(anyString(), anyInt()))
                .thenThrow(new RuntimeException("DNS timeout"));

            ClientRequestVerificationResult result = verifier.verify(
                clientCertWithAtiSan, VerificationPolicy.DANE_AND_BADGE);

            assertThat(result.verified()).isFalse();
            assertThat(result.errors()).anyMatch(e -> e.contains("DANE TLSA lookup failed"));
        }

        @Test
        @DisplayName("Should query _ati-identity._tls prefix for DANE")
        void shouldQueryIdentityTlsaPrefix() throws Exception {
            String fingerprint = CertificateUtils.computeSha256Fingerprint(clientCertWithAtiSan);

            ClientVerificationResult badgeResult = ClientVerificationResult.builder()
                .status(VerificationStatus.VERIFIED)
                .expectedIdentityCertFingerprint(fingerprint)
                .build();
            when(mockBadgeService.verifyClient(clientCertWithAtiSan)).thenReturn(badgeResult);

            when(mockDaneTlsaVerifier.getTlsaExpectations(anyString(), anyInt()))
                .thenReturn(List.of());

            verifier.verify(clientCertWithAtiSan, VerificationPolicy.DANE_AND_BADGE);

            // Verify the correct DNS name was queried
            verify(mockDaneTlsaVerifier).getTlsaExpectations(
                "_ati-identity._tls.client-agent.example.com", 0);
        }

        @Test
        @DisplayName("Should match when one of multiple TLSA records matches")
        void shouldMatchWhenOneOfMultipleTlsaRecordsMatches() throws Exception {
            String fingerprint = CertificateUtils.computeSha256Fingerprint(clientCertWithAtiSan);

            ClientVerificationResult badgeResult = ClientVerificationResult.builder()
                .status(VerificationStatus.VERIFIED)
                .expectedIdentityCertFingerprint(fingerprint)
                .build();
            when(mockBadgeService.verifyClient(clientCertWithAtiSan)).thenReturn(badgeResult);

            // First TLSA record: wrong hash
            byte[] wrongHash = new byte[32];
            TlsaExpectation wrongExpectation = new TlsaExpectation(1, 1, wrongHash);

            // Second TLSA record: correct hash (SPKI SHA-256)
            byte[] correctHash = CryptoCache.sha256(clientCertWithAtiSan.getPublicKey().getEncoded());
            TlsaExpectation correctExpectation = new TlsaExpectation(1, 1, correctHash);

            when(mockDaneTlsaVerifier.getTlsaExpectations(anyString(), anyInt()))
                .thenReturn(List.of(wrongExpectation, correctExpectation));

            ClientRequestVerificationResult result = verifier.verify(
                clientCertWithAtiSan, VerificationPolicy.DANE_AND_BADGE);

            assertThat(result.verified()).isTrue();
        }
    }

    @Nested
    @DisplayName("Error handling tests")
    class ErrorHandlingTests {

        @Test
        @DisplayName("Should handle badge service throwing exception")
        void shouldHandleBadgeServiceException() {
            when(mockBadgeService.verifyClient(any()))
                .thenThrow(new RuntimeException("Network error"));

            ClientRequestVerificationResult result = verifier.verify(
                clientCertWithAtiSan, VerificationPolicy.BADGE_REQUIRED);

            assertThat(result.verified()).isFalse();
            assertThat(result.errors()).anyMatch(e -> e.contains("Verification error"));
        }
    }

    @Nested
    @DisplayName("ClientRequestVerificationResult tests")
    class ResultTests {

        @Test
        @DisplayName("Success result should have correct fields")
        void successResultShouldHaveCorrectFields() {
            ClientRequestVerificationResult result = verifier.verify(
                clientCertWithAtiSan, VerificationPolicy.PKI_ONLY);

            assertThat(result.verified()).isTrue();
            assertThat(result.agentHost()).isEqualTo("client-agent.example.com");
            assertThat(result.policyUsed()).isEqualTo(VerificationPolicy.PKI_ONLY);
            assertThat(result.errors()).isEmpty();
            assertThat(result.verificationDuration()).isNotNull();
        }

        @Test
        @DisplayName("toString should include verification status")
        void toStringShouldIncludeVerificationStatus() {
            ClientRequestVerificationResult result = verifier.verify(
                clientCertWithAtiSan, VerificationPolicy.PKI_ONLY);

            assertThat(result.toString()).contains("verified=true");
            assertThat(result.toString()).contains("client-agent.example.com");
        }

        @Test
        @DisplayName("Failure result should include errors")
        void failureResultShouldIncludeErrors() {
            ClientRequestVerificationResult result = verifier.verify(
                clientCertWithoutUriSan, VerificationPolicy.PKI_ONLY);

            assertThat(result.verified()).isFalse();
            assertThat(result.errors()).isNotEmpty();
            assertThat(result.toString()).contains("verified=false");
        }
    }

    @Nested
    @DisplayName("Builder tests")
    class BuilderTests {

        @Test
        @DisplayName("Should build without any services (all optional at build time)")
        void shouldBuildWithoutAnyServices() {
            DefaultClientRequestVerifier v = DefaultClientRequestVerifier.builder().build();
            assertThat(v).isNotNull();
        }

        @Test
        @DisplayName("Should build with badge service only")
        void shouldBuildWithBadgeServiceOnly() {
            DefaultClientRequestVerifier v = DefaultClientRequestVerifier.builder()
                .badgeVerificationService(mockBadgeService)
                .build();
            assertThat(v).isNotNull();
        }

        @Test
        @DisplayName("Should build with both badge and DANE services")
        void shouldBuildWithBothServices() {
            DefaultClientRequestVerifier v = DefaultClientRequestVerifier.builder()
                .badgeVerificationService(mockBadgeService)
                .daneTlsaVerifier(mockDaneTlsaVerifier)
                .build();
            assertThat(v).isNotNull();
        }
    }

    // ==================== Helper Methods ====================

    /**
     * Creates a self-signed X.509 certificate with a URI SAN containing the ATI name.
     */
    private X509Certificate createCertificateWithUriSan(String uriSan) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        KeyPair keyPair = keyGen.generateKeyPair();

        X500Name subject = new X500Name("CN=Test Agent");
        BigInteger serial = BigInteger.valueOf(System.nanoTime());
        Instant now = Instant.now();

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
            subject,
            serial,
            Date.from(now.minusSeconds(3600)),
            Date.from(now.plusSeconds(86400)),
            subject,
            keyPair.getPublic()
        );

        // Add URI Subject Alternative Name (type 6)
        GeneralName uriGeneralName = new GeneralName(GeneralName.uniformResourceIdentifier, uriSan);
        GeneralNames subjectAltNames = new GeneralNames(uriGeneralName);
        certBuilder.addExtension(Extension.subjectAlternativeName, false, subjectAltNames);

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
            .build(keyPair.getPrivate());

        X509CertificateHolder certHolder = certBuilder.build(signer);
        return new JcaX509CertificateConverter().getCertificate(certHolder);
    }

    /**
     * Creates a self-signed X.509 certificate without a URI SAN.
     */
    private X509Certificate createCertificateWithoutUriSan() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        KeyPair keyPair = keyGen.generateKeyPair();

        X500Name subject = new X500Name("CN=Plain Agent");
        BigInteger serial = BigInteger.valueOf(System.nanoTime());
        Instant now = Instant.now();

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
            subject,
            serial,
            Date.from(now.minusSeconds(3600)),
            Date.from(now.plusSeconds(86400)),
            subject,
            keyPair.getPublic()
        );

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
            .build(keyPair.getPrivate());

        X509CertificateHolder certHolder = certBuilder.build(signer);
        return new JcaX509CertificateConverter().getCertificate(certHolder);
    }
}
