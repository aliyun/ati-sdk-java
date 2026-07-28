package com.aliyun.ati.sdk.agent.http;

import com.aliyun.ati.sdk.agent.ConnectOptions;
import com.aliyun.ati.sdk.agent.VerificationPolicy;
import com.aliyun.ati.sdk.transparency.TransparencyClient;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.StringWriter;
import java.math.BigInteger;
import java.net.http.HttpClient;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Date;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.mock;

/**
 * mTLS client certificate tests for {@link DefaultAgentHttpClientFactory}.
 */
class DefaultAgentHttpClientFactoryMtlsTest {

    // ==================== mTLS Client Certificate Tests ====================

    @Test
    void createVerifiedWithPreLoadedClientCertificate() throws Exception {
        // Tests the loadKeyManagers path with pre-loaded certificate
        DefaultAgentHttpClientFactory factory = new DefaultAgentHttpClientFactory();

        // Generate a test certificate and key pair
        KeyPair keyPair = generateTestKeyPair();
        X509Certificate cert = createTestCertificate("CN=TestClient", keyPair);

        ConnectOptions options = ConnectOptions.builder()
            .verificationPolicy(VerificationPolicy.BASIC)
            .clientCertificate(cert, keyPair.getPrivate())
            .build();

        VerifiedClientResult result = factory.createVerified(
            "example.com", options, Duration.ofSeconds(10));

        assertNotNull(result);
        assertNotNull(result.atiHttpClient());
    }

    @Test
    void createWithPreLoadedClientCertificate() throws Exception {
        // Tests create() path with pre-loaded certificate
        DefaultAgentHttpClientFactory factory = new DefaultAgentHttpClientFactory();

        KeyPair keyPair = generateTestKeyPair();
        X509Certificate cert = createTestCertificate("CN=TestClient", keyPair);

        ConnectOptions options = ConnectOptions.builder()
            .verificationPolicy(VerificationPolicy.BASIC)
            .clientCertificate(cert, keyPair.getPrivate())
            .build();

        HttpClient client = factory.create("example.com", options, Duration.ofSeconds(10));

        assertNotNull(client);
    }

    @Test
    void createVerifiedWithMtlsAndDaneVerification() throws Exception {
        // Tests mTLS combined with DANE verification
        DefaultAgentHttpClientFactory factory = new DefaultAgentHttpClientFactory();

        KeyPair keyPair = generateTestKeyPair();
        X509Certificate cert = createTestCertificate("CN=TestClient", keyPair);

        ConnectOptions options = ConnectOptions.builder()
            .verificationPolicy(VerificationPolicy.ADVANCED)
            .clientCertificate(cert, keyPair.getPrivate())
            .transparencyClient(mock(TransparencyClient.class))
            .build();

        VerifiedClientResult result = factory.createVerified(
            "example.com", options, Duration.ofSeconds(10));

        assertNotNull(result);
        assertNotNull(result.verifier());
    }

    @Test
    void createVerifiedWithMtlsAndBadgeVerification() throws Exception {
        // Tests mTLS combined with Badge verification
        DefaultAgentHttpClientFactory factory = new DefaultAgentHttpClientFactory();
        TransparencyClient mockTransparencyClient = mock(TransparencyClient.class);

        KeyPair keyPair = generateTestKeyPair();
        X509Certificate cert = createTestCertificate("CN=TestClient", keyPair);

        ConnectOptions options = ConnectOptions.builder()
            .verificationPolicy(VerificationPolicy.ENHANCED)
            .transparencyClient(mockTransparencyClient)
            .clientCertificate(cert, keyPair.getPrivate())
            .build();

        VerifiedClientResult result = factory.createVerified(
            "example.com", options, Duration.ofSeconds(10));

        assertNotNull(result);
    }

    @Test
    void createVerifiedWithMtlsAndDaneAndBadgeVerification() throws Exception {
        // Tests mTLS combined with both DANE and Badge verification
        DefaultAgentHttpClientFactory factory = new DefaultAgentHttpClientFactory();
        TransparencyClient mockTransparencyClient = mock(TransparencyClient.class);

        KeyPair keyPair = generateTestKeyPair();
        X509Certificate cert = createTestCertificate("CN=TestClient", keyPair);

        ConnectOptions options = ConnectOptions.builder()
            .verificationPolicy(VerificationPolicy.ADVANCED)
            .transparencyClient(mockTransparencyClient)
            .clientCertificate(cert, keyPair.getPrivate())
            .build();

        VerifiedClientResult result = factory.createVerified(
            "example.com", options, Duration.ofSeconds(10));

        assertNotNull(result);
    }

    @Test
    void createVerifiedWithFileCertificatePaths(@TempDir Path tempDir) throws Exception {
        // Tests the loadKeyManagers path with file-based certificate loading
        DefaultAgentHttpClientFactory factory = new DefaultAgentHttpClientFactory();

        // Generate test certificates dynamically
        KeyPair keyPair = generateTestKeyPair();
        X509Certificate cert = createTestCertificate("CN=test.example.com", keyPair);
        Path certPath = writeCertToPem(tempDir.resolve("test-cert.pem"), cert);
        Path keyPath = writeKeyToPem(tempDir.resolve("test-key.pem"), keyPair);

        ConnectOptions options = ConnectOptions.builder()
            .verificationPolicy(VerificationPolicy.BASIC)
            .clientCertPath(certPath, keyPath)
            .build();

        VerifiedClientResult result = factory.createVerified(
            "example.com", options, Duration.ofSeconds(10));

        assertNotNull(result);
        assertNotNull(result.atiHttpClient());
    }

    @Test
    void createWithFileCertificatePaths(@TempDir Path tempDir) throws Exception {
        // Tests create() path with file-based certificate loading
        DefaultAgentHttpClientFactory factory = new DefaultAgentHttpClientFactory();

        // Generate test certificates dynamically
        KeyPair keyPair = generateTestKeyPair();
        X509Certificate cert = createTestCertificate("CN=test.example.com", keyPair);
        Path certPath = writeCertToPem(tempDir.resolve("test-cert.pem"), cert);
        Path keyPath = writeKeyToPem(tempDir.resolve("test-key.pem"), keyPair);

        ConnectOptions options = ConnectOptions.builder()
            .verificationPolicy(VerificationPolicy.BASIC)
            .clientCertPath(certPath, keyPath)
            .build();

        HttpClient client = factory.create("example.com", options, Duration.ofSeconds(10));

        assertNotNull(client);
    }

    @Test
    void createVerifiedWithFileCertificatePathsAndDane(@TempDir Path tempDir) throws Exception {
        // Tests file-based mTLS combined with DANE verification
        DefaultAgentHttpClientFactory factory = new DefaultAgentHttpClientFactory();

        // Generate test certificates dynamically
        KeyPair keyPair = generateTestKeyPair();
        X509Certificate cert = createTestCertificate("CN=test.example.com", keyPair);
        Path certPath = writeCertToPem(tempDir.resolve("test-cert.pem"), cert);
        Path keyPath = writeKeyToPem(tempDir.resolve("test-key.pem"), keyPair);

        ConnectOptions options = ConnectOptions.builder()
            .verificationPolicy(VerificationPolicy.ADVANCED)
            .clientCertPath(certPath, keyPath)
            .transparencyClient(mock(TransparencyClient.class))
            .build();

        VerifiedClientResult result = factory.createVerified(
            "example.com", options, Duration.ofSeconds(10));

        assertNotNull(result);
    }

    // ==================== Helper Methods ====================

    private KeyPair generateTestKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048, new SecureRandom());
        return keyGen.generateKeyPair();
    }

    private X509Certificate createTestCertificate(String subjectDn, KeyPair keyPair) throws Exception {
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

    private Path writeCertToPem(Path path, X509Certificate cert) throws Exception {
        StringWriter sw = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(sw)) {
            pemWriter.writeObject(cert);
        }
        Files.writeString(path, sw.toString());
        return path;
    }

    private Path writeKeyToPem(Path path, KeyPair keyPair) throws Exception {
        // Write PKCS#8 format (BEGIN PRIVATE KEY) instead of PKCS#1 (BEGIN RSA PRIVATE KEY)
        byte[] encoded = keyPair.getPrivate().getEncoded();
        String base64 = java.util.Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(encoded);
        String pem = "-----BEGIN PRIVATE KEY-----\n" + base64 + "\n-----END PRIVATE KEY-----\n";
        Files.writeString(path, pem);
        return path;
    }
}
