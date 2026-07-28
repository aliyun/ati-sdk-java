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
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class DefaultClientRequestVerifierAdvancedPolicyTest {

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
            when(mockDaneTlsaVerifier.getTlsaExpectations(anyString()))
                .thenReturn(List.of(tlsaExpectation));

            ClientRequestVerificationResult result = verifier.verify(
                clientCertWithAtiSan, VerificationPolicy.ADVANCED);

            assertThat(result.verified()).isTrue();
            assertThat(result.policyUsed()).isEqualTo(VerificationPolicy.ADVANCED);
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
            when(mockDaneTlsaVerifier.getTlsaExpectations(anyString()))
                .thenReturn(List.of());

            ClientRequestVerificationResult result = verifier.verify(
                clientCertWithAtiSan, VerificationPolicy.ADVANCED);

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
            when(mockDaneTlsaVerifier.getTlsaExpectations(anyString()))
                .thenReturn(List.of(tlsaExpectation));

            ClientRequestVerificationResult result = verifier.verify(
                clientCertWithAtiSan, VerificationPolicy.ADVANCED);

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
                clientCertWithAtiSan, VerificationPolicy.ADVANCED);

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
                clientCertWithAtiSan, VerificationPolicy.ADVANCED);

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

            when(mockDaneTlsaVerifier.getTlsaExpectations(anyString()))
                .thenThrow(new RuntimeException("DNS timeout"));

            ClientRequestVerificationResult result = verifier.verify(
                clientCertWithAtiSan, VerificationPolicy.ADVANCED);

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

            when(mockDaneTlsaVerifier.getTlsaExpectations(anyString()))
                .thenReturn(List.of());

            verifier.verify(clientCertWithAtiSan, VerificationPolicy.ADVANCED);

            // Verify the correct DNS name was queried
            verify(mockDaneTlsaVerifier).getTlsaExpectations(
                "_ati-identity._tls.client-agent.example.com");
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

            when(mockDaneTlsaVerifier.getTlsaExpectations(anyString()))
                .thenReturn(List.of(wrongExpectation, correctExpectation));

            ClientRequestVerificationResult result = verifier.verify(
                clientCertWithAtiSan, VerificationPolicy.ADVANCED);

            assertThat(result.verified()).isTrue();
        }
    }


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
