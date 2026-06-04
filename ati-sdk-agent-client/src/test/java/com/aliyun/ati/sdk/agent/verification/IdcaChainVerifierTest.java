package com.aliyun.ati.sdk.agent.verification;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.Date;
import java.util.List;

import javax.net.ssl.X509TrustManager;

import com.aliyun.ati.sdk.exception.AtiException;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class IdcaChainVerifierTest {

    private static X509Certificate rootCaCert;
    private static X509Certificate leafCert;
    private static X509Certificate unrelatedCaCert;
    private static X509Certificate unrelatedLeafCert;
    private static X509Certificate intermediateCaCert;
    private static X509Certificate intermediateLeafCert;

    @BeforeAll
    static void generateCertificates() throws Exception {
        // Generate root CA key pair and self-signed certificate
        KeyPair rootKeyPair = generateEcKeyPair();
        rootCaCert = generateSelfSignedCa(
            rootKeyPair, "CN=ATI Test Root CA");

        // Generate leaf certificate signed by root CA
        KeyPair leafKeyPair = generateEcKeyPair();
        leafCert = generateLeafCert(
            leafKeyPair, rootKeyPair, rootCaCert, "CN=test-agent.example.com");

        // Generate an unrelated CA and leaf (different trust chain)
        KeyPair unrelatedKeyPair = generateEcKeyPair();
        unrelatedCaCert = generateSelfSignedCa(
            unrelatedKeyPair, "CN=Unrelated CA");

        KeyPair unrelatedLeafKeyPair = generateEcKeyPair();
        unrelatedLeafCert = generateLeafCert(
            unrelatedLeafKeyPair, unrelatedKeyPair,
            unrelatedCaCert, "CN=unrelated-agent.example.com");

        // Generate intermediate CA signed by root CA
        KeyPair intermediateKeyPair = generateEcKeyPair();
        intermediateCaCert = generateIntermediateCa(
            intermediateKeyPair, rootKeyPair, rootCaCert,
            "CN=ATI Test Intermediate CA");

        // Generate leaf certificate signed by intermediate CA
        KeyPair intermediateLeafKeyPair = generateEcKeyPair();
        intermediateLeafCert = generateLeafCert(
            intermediateLeafKeyPair, intermediateKeyPair,
            intermediateCaCert, "CN=intermediate-agent.example.com");
    }

    @Test
    void createTrustManagerShouldAcceptCertSignedByTrustAnchor()
            throws Exception {
        IdcaChainVerifier verifier =
            new IdcaChainVerifier(List.of(rootCaCert));
        X509TrustManager tm = verifier.createTrustManager();
        // Should not throw — leafCert is signed by rootCaCert
        tm.checkServerTrusted(
            new X509Certificate[]{leafCert}, "ECDHE_ECDSA");
    }

    @Test
    void createTrustManagerShouldRejectCertFromDifferentCA() {
        IdcaChainVerifier verifier =
            new IdcaChainVerifier(List.of(rootCaCert));
        X509TrustManager tm = verifier.createTrustManager();
        // Should throw — unrelatedLeafCert is not signed by rootCaCert
        assertThatThrownBy(() -> tm.checkServerTrusted(
                new X509Certificate[]{unrelatedLeafCert},
                "ECDHE_ECDSA"))
            .isInstanceOf(
                java.security.cert.CertificateException.class);
    }

    @Test
    void createTrustManagerShouldWorkWithIntermediateChain()
            throws Exception {
        IdcaChainVerifier verifier = new IdcaChainVerifier(
            List.of(intermediateCaCert, rootCaCert));
        X509TrustManager tm = verifier.createTrustManager();
        // Should not throw — intermediateLeafCert is signed by
        // intermediateCaCert which chains to rootCaCert
        tm.checkServerTrusted(
            new X509Certificate[]{intermediateLeafCert,
                intermediateCaCert},
            "ECDHE_ECDSA");
    }

    @Test
    void createTrustManagerShouldReturnNonNull() {
        IdcaChainVerifier verifier =
            new IdcaChainVerifier(List.of(rootCaCert));
        X509TrustManager tm = verifier.createTrustManager();
        assertThat(tm).isNotNull();
        assertThat(tm.getAcceptedIssuers()).isNotEmpty();
    }

    @Test
    void shouldThrowForNullPath() {
        assertThatThrownBy(() -> new IdcaChainVerifier((String) null))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("trustCertificatePath");
    }

    @Test
    void shouldThrowForMissingFile() {
        assertThatThrownBy(
            () -> new IdcaChainVerifier("/nonexistent/path/ca.pem"))
            .isInstanceOf(AtiException.class)
            .hasMessageContaining("Failed to load IDCA certificates");
    }

    @Test
    void shouldThrowForMissingClasspathResource() {
        assertThatThrownBy(
            () -> new IdcaChainVerifier(
                "classpath:nonexistent/idca-chain.pem"))
            .isInstanceOf(AtiException.class)
            .hasMessageContaining("not found on classpath");
    }

    @Test
    void shouldThrowForEmptyChainCerts() {
        assertThatThrownBy(
            () -> new IdcaChainVerifier(Collections.emptyList()))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("must not be empty");
    }

    @Test
    void shouldLoadTrustCertsFromClasspath() {
        IdcaChainVerifier verifier =
            new IdcaChainVerifier("classpath:idca/test-ca.crt");
        X509TrustManager tm = verifier.createTrustManager();
        assertThat(tm).isNotNull();
        assertThat(tm.getAcceptedIssuers()).isNotEmpty();
    }

    private static KeyPair generateEcKeyPair() throws Exception {
        KeyPairGenerator kpg =
            KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        return kpg.generateKeyPair();
    }

    private static X509Certificate generateSelfSignedCa(
            KeyPair keyPair, String dn) throws Exception {
        Instant now = Instant.now();
        X500Name issuer = new X500Name(dn);

        JcaX509v3CertificateBuilder builder =
            new JcaX509v3CertificateBuilder(
                issuer,
                BigInteger.valueOf(1),
                Date.from(now),
                Date.from(now.plus(365, ChronoUnit.DAYS)),
                issuer,
                keyPair.getPublic());

        builder.addExtension(
            Extension.basicConstraints, true,
            new BasicConstraints(true));

        ContentSigner signer = new JcaContentSignerBuilder(
            "SHA256withECDSA").build(keyPair.getPrivate());
        X509CertificateHolder holder = builder.build(signer);

        return new JcaX509CertificateConverter()
            .getCertificate(holder);
    }

    private static X509Certificate generateIntermediateCa(
            KeyPair intermediateKeyPair, KeyPair rootKeyPair,
            X509Certificate rootCert,
            String subjectDn) throws Exception {
        Instant now = Instant.now();
        X500Name issuer =
            new X500Name(rootCert.getSubjectX500Principal().getName());
        X500Name subject = new X500Name(subjectDn);

        JcaX509v3CertificateBuilder builder =
            new JcaX509v3CertificateBuilder(
                issuer,
                BigInteger.valueOf(3),
                Date.from(now),
                Date.from(now.plus(180, ChronoUnit.DAYS)),
                subject,
                intermediateKeyPair.getPublic());

        // Mark as CA with pathLen 0 (can sign leaf certs only)
        builder.addExtension(
            Extension.basicConstraints, true,
            new BasicConstraints(0));

        ContentSigner signer = new JcaContentSignerBuilder(
            "SHA256withECDSA").build(rootKeyPair.getPrivate());
        X509CertificateHolder holder = builder.build(signer);

        return new JcaX509CertificateConverter()
            .getCertificate(holder);
    }

    private static X509Certificate generateLeafCert(
            KeyPair leafKeyPair, KeyPair issuerKeyPair,
            X509Certificate issuerCert,
            String subjectDn) throws Exception {
        Instant now = Instant.now();
        X500Name issuer =
            new X500Name(issuerCert.getSubjectX500Principal().getName());
        X500Name subject = new X500Name(subjectDn);

        JcaX509v3CertificateBuilder builder =
            new JcaX509v3CertificateBuilder(
                issuer,
                BigInteger.valueOf(2),
                Date.from(now),
                Date.from(now.plus(30, ChronoUnit.DAYS)),
                subject,
                leafKeyPair.getPublic());

        builder.addExtension(
            Extension.basicConstraints, true,
            new BasicConstraints(false));

        ContentSigner signer = new JcaContentSignerBuilder(
            "SHA256withECDSA").build(issuerKeyPair.getPrivate());
        X509CertificateHolder holder = builder.build(signer);

        return new JcaX509CertificateConverter()
            .getCertificate(holder);
    }
}
