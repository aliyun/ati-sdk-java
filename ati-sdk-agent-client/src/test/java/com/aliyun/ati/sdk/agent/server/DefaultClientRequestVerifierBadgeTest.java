package com.aliyun.ati.sdk.agent.server;

import com.aliyun.ati.sdk.agent.VerificationPolicy;
import com.aliyun.ati.sdk.agent.verification.DaneTlsaVerifier;
import com.aliyun.ati.sdk.crypto.CertificateUtils;
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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class DefaultClientRequestVerifierBadgeTest {

    private BadgeVerificationService mockBadgeService;
    private DaneTlsaVerifier mockDaneTlsaVerifier;
    private DefaultClientRequestVerifier verifier;
    private X509Certificate clientCertWithAtiSan;

    @BeforeEach
    void setUp() throws Exception {
        mockBadgeService = mock(BadgeVerificationService.class);
        mockDaneTlsaVerifier = mock(DaneTlsaVerifier.class);
        verifier = DefaultClientRequestVerifier.builder()
            .badgeVerificationService(mockBadgeService)
            .daneTlsaVerifier(mockDaneTlsaVerifier)
            .build();
        clientCertWithAtiSan = createCertificateWithUriSan("ati://v1.client-agent.example.com");
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
                clientCertWithAtiSan, VerificationPolicy.ENHANCED);

            assertThat(result.verified()).isTrue();
            assertThat(result.agentHost()).isEqualTo("client-agent.example.com");
            assertThat(result.policyUsed()).isEqualTo(VerificationPolicy.ENHANCED);
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
                clientCertWithAtiSan, VerificationPolicy.ENHANCED);

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
                clientCertWithAtiSan, VerificationPolicy.ENHANCED);

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
                clientCertWithAtiSan, VerificationPolicy.ENHANCED);

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
                clientCertWithAtiSan, VerificationPolicy.ENHANCED);

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
                clientCertWithAtiSan, VerificationPolicy.ENHANCED);

            assertThat(result.verified()).isTrue();
        }

        @Test
        @DisplayName("Should fail when badgeVerificationService is not configured")
        void shouldFailWhenBadgeServiceNotConfigured() {
            DefaultClientRequestVerifier noBadgeVerifier = DefaultClientRequestVerifier.builder()
                .build();

            ClientRequestVerificationResult result = noBadgeVerifier.verify(
                clientCertWithAtiSan, VerificationPolicy.ENHANCED);

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

            verifier.verify(clientCertWithAtiSan, VerificationPolicy.ENHANCED);

            verify(mockDaneTlsaVerifier, never()).getTlsaExpectations(anyString());
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
