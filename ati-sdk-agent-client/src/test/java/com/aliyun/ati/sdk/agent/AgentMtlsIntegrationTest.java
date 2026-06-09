package com.aliyun.ati.sdk.agent;

import java.io.OutputStream;
import java.math.BigInteger;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import com.aliyun.ati.sdk.agent.http.CertificateCapturingTrustManager;
import com.aliyun.ati.sdk.agent.verification.BadgeVerifier;
import com.aliyun.ati.sdk.agent.verification.DaneTlsaVerifier;
import com.aliyun.ati.sdk.agent.verification.PreVerificationResult;
import com.aliyun.ati.sdk.agent.verification.VerificationResult;
import com.aliyun.ati.sdk.crypto.CertUtils;
import com.aliyun.ati.sdk.discovery.AtiAgentDescriptor;
import com.aliyun.ati.sdk.transparency.AtiTransparencyClient;
import com.aliyun.ati.sdk.transparency.model.TransparencyLogResponse;
import com.aliyun.ati.sdk.transparency.verification.BadgeVerificationService;
import com.aliyun.ati.sdk.transparency.verification.CachingBadgeVerificationService;
import com.aliyun.ati.sdk.transparency.verification.MerkleProofVerifier;
import com.aliyun.ati.sdk.transparency.verification.ServerVerificationResult;
import com.aliyun.ati.sdk.transparency.verification.TlSealVerifier;
import com.aliyun.ati.sdk.transparency.verification.VerificationStatus;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.erdtman.jcs.JsonCanonicalizer;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsParameters;
import com.sun.net.httpserver.HttpsServer;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Integration test validating the full mTLS connection flow between two ATI agents.
 * Uses the dual-cert model: "Public CA" chain for server TLS, IDCA chain for mTLS client auth.
 * The mock HTTPS server requires client authentication ({@code needClientAuth=true}).
 */
class AgentMtlsIntegrationTest {

    private static KeyPair publicCaKeyPair;
    private static X509Certificate publicCaRootCert;
    private static KeyPair serverKeyPair;
    private static X509Certificate serverCert;
    private static KeyPair idcaKeyPair;
    private static X509Certificate idcaRootCert;
    private static KeyPair identityKeyPair;
    private static X509Certificate identityCert;
    private static KeyPair tlKeyPair;
    private static HttpsServer httpsServer;
    private static int serverPort;

    @BeforeAll
    static void setUp() throws Exception {
        generateCertificates();
        startMockServer();
    }

    @AfterAll
    static void tearDown() {
        if (httpsServer != null) {
            httpsServer.stop(0);
        }
    }

    @Test
    void shouldCompleteMtlsHandshake() throws Exception {
        HttpClient httpClient = HttpClient.newBuilder()
            .sslContext(buildMtlsSslContext(
                identityKeyPair, identityCert, publicCaRootCert))
            .build();
        HttpResponse<String> response = sendHello(httpClient);
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).contains("ok");
    }

    @Test
    void shouldRejectClientWithoutIdentityCert() throws Exception {
        KeyStore ts = KeyStore.getInstance(KeyStore.getDefaultType());
        ts.load(null, null);
        ts.setCertificateEntry("public-ca", publicCaRootCert);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(
            TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ts);
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, tmf.getTrustManagers(), null);
        HttpClient httpClient = HttpClient.newBuilder().sslContext(sslContext).build();
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://localhost:" + serverPort + "/api/hello"))
            .GET().build();
        assertThatThrownBy(() -> httpClient.send(request, HttpResponse.BodyHandlers.ofString()))
            .isInstanceOf(Exception.class);
    }

    @Test
    void shouldRejectClientWithWrongCaCert() throws Exception {
        KeyPair wrongCaKeyPair = generateEcKeyPair();
        X509Certificate wrongCaRoot = generateSelfSignedCa(wrongCaKeyPair, "CN=Wrong CA");
        KeyPair wrongIdKp = generateEcKeyPair();
        X509Certificate wrongIdCert = generateLeafCert(
            wrongIdKp, wrongCaKeyPair, wrongCaRoot, "CN=wrong-agent");
        HttpClient httpClient = HttpClient.newBuilder()
            .sslContext(buildMtlsSslContext(wrongIdKp, wrongIdCert, publicCaRootCert))
            .build();
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://localhost:" + serverPort + "/api/hello"))
            .GET().build();
        assertThatThrownBy(() -> httpClient.send(request, HttpResponse.BodyHandlers.ofString()))
            .isInstanceOf(Exception.class);
    }

    @Test
    void shouldCompleteFullVerificationWithDaneAndBadge() throws Exception {
        CertificateCapturingTrustManager capturingTm = buildCapturingTrustManager();
        HttpClient httpClient = buildCapturingHttpClient(capturingTm);

        byte[] spkiHash = MessageDigest.getInstance("SHA-256")
            .digest(serverCert.getPublicKey().getEncoded());
        DaneTlsaVerifier.TlsaExpectation daneExpectation =
            new DaneTlsaVerifier.TlsaExpectation(1, 1, spkiHash);
        String serverFingerprint = CertUtils.sha256Fingerprint(serverCert);
        ServerVerificationResult badgeTlResult =
            ServerVerificationResult.verified(serverFingerprint, "test-agent");
        AtiAgentDescriptor descriptor = new AtiAgentDescriptor(
            "localhost", "1", null, "test-agent");
        PreVerificationResult preResult = new PreVerificationResult(
            descriptor, VerificationPolicy.GOLD,
            List.of(daneExpectation), badgeTlResult);

        assertThat(sendHello(httpClient).statusCode()).isEqualTo(200);
        X509Certificate capturedCert = capturingTm.getLastCapturedServerCert();
        assertThat(capturedCert).isNotNull();

        DaneTlsaVerifier daneVerifier = new DaneTlsaVerifier();
        VerificationResult daneResult = daneVerifier.postVerify(
            capturedCert, List.of(daneExpectation));
        assertThat(daneResult.isSuccess()).isTrue();
        assertThat(daneResult.getType()).isEqualTo(VerificationResult.Type.DANE);

        BadgeVerifier badgeVerifier = new BadgeVerifier(
            mock(CachingBadgeVerificationService.class));
        VerificationResult badgeResult = badgeVerifier.postVerify(
            capturedCert, badgeTlResult);
        assertThat(badgeResult.isSuccess()).isTrue();
        assertThat(badgeResult.getType()).isEqualTo(VerificationResult.Type.BADGE);
    }

    @Test
    void shouldFailDaneWhenFingerprintMismatch() throws Exception {
        CertificateCapturingTrustManager capturingTm = buildCapturingTrustManager();
        HttpClient httpClient = buildCapturingHttpClient(capturingTm);
        sendHello(httpClient);

        DaneTlsaVerifier.TlsaExpectation wrongExpectation =
            new DaneTlsaVerifier.TlsaExpectation(1, 1, new byte[32]);
        VerificationResult daneResult = new DaneTlsaVerifier().postVerify(
            capturingTm.getLastCapturedServerCert(), List.of(wrongExpectation));
        assertThat(daneResult.isSuccess()).isFalse();
        assertThat(daneResult.getStatus()).isEqualTo(VerificationResult.Status.MISMATCH);
    }

    @Test
    void shouldCompleteFullBadgeWithSealAndMerkle() throws Exception {
        CertificateCapturingTrustManager capturingTm = buildCapturingTrustManager();
        HttpClient httpClient = buildCapturingHttpClient(capturingTm);
        assertThat(sendHello(httpClient).statusCode()).isEqualTo(200);

        X509Certificate capturedCert = capturingTm.getLastCapturedServerCert();
        assertThat(capturedCert).isNotNull();
        String expectedFingerprint = CertUtils.sha256Fingerprint(capturedCert);

        // Build content map for seal signing (must match TlSealVerifier field order)
        Map<String, Object> certsMap = new LinkedHashMap<>();
        certsMap.put("serverCertFingerprint", expectedFingerprint);
        Map<String, Object> payloadMap = new LinkedHashMap<>();
        payloadMap.put("agentId", "test-agent");
        payloadMap.put("agentHost", "agent.example.com");
        payloadMap.put("certificates", certsMap);
        Map<String, Object> evidenceRefMap = new LinkedHashMap<>();
        evidenceRefMap.put("evidenceId", "ev-001");
        evidenceRefMap.put("evidenceUri", "https://example.com/evidence");
        Map<String, Object> content = new LinkedHashMap<>();
        content.put("status", "ACTIVE");
        content.put("schemaVersion", "ATI-TL-V1");
        content.put("payload", payloadMap);
        content.put("evidenceRef", evidenceRefMap);

        ObjectMapper mapper = new ObjectMapper();
        mapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
        byte[] canonicalBytes = new JsonCanonicalizer(
            mapper.writeValueAsString(content)).getEncodedUTF8();

        // Sign with TL key pair
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(tlKeyPair.getPrivate());
        sig.update(canonicalBytes);
        String sealSignature = Base64.getEncoder().encodeToString(sig.sign());
        String tlPubPem = "-----BEGIN PUBLIC KEY-----\\n"
            + Base64.getEncoder().encodeToString(tlKeyPair.getPublic().getEncoded())
            + "\\n-----END PUBLIC KEY-----";

        // Merkle proof: single-leaf tree (leafHash == rootHash, empty path)
        String leafHash = bytesToHex(
            MessageDigest.getInstance("SHA-256").digest(canonicalBytes));

        String responseJson = """
            {"status":"ACTIVE","schemaVersion":"ATI-TL-V1",\
            "payload":{"agentId":"test-agent","agentHost":"agent.example.com",\
            "certificates":{"serverCertFingerprint":"%s"}},\
            "evidenceRef":{"evidenceId":"ev-001",\
            "evidenceUri":"https://example.com/evidence"},\
            "seal":{"canonicalization":"RFC8785-JCS","digestAlgorithm":"SHA-256",\
            "signatureAlgorithm":"SHA-256withECDSA","signatureEncoding":"DER_BASE64",\
            "keyId":"tl-key-001","signature":"%s","publicKey":"%s"},\
            "merkleProof":{"leafHash":"%s","leafIndex":0,"treeSize":1,\
            "treeVersion":1,"path":[],"rootHash":"%s"}}
            """.formatted(expectedFingerprint, sealSignature, tlPubPem,
                leafHash, leafHash);

        TransparencyLogResponse tlResponse = mapper.readValue(
            responseJson, TransparencyLogResponse.class);

        AtiTransparencyClient mockTlClient = mock(AtiTransparencyClient.class);
        when(mockTlClient.getLatestLog("test-agent")).thenReturn(tlResponse);

        BadgeVerificationService badgeService = new BadgeVerificationService(
            mockTlClient, new TlSealVerifier(), new MerkleProofVerifier());
        ServerVerificationResult result = badgeService.verifyServer("test-agent");
        assertThat(result.getStatus()).isEqualTo(VerificationStatus.VERIFIED);
        assertThat(result.getServerCertFingerprint()).isEqualTo(expectedFingerprint);
        assertThat(result.getAgentId()).isEqualTo("test-agent");
    }

    // --- Helpers ---

    private static HttpResponse<String> sendHello(HttpClient client) throws Exception {
        return client.send(HttpRequest.newBuilder()
            .uri(URI.create("https://localhost:" + serverPort + "/api/hello"))
            .GET().build(), HttpResponse.BodyHandlers.ofString());
    }

    private static SSLContext buildMtlsSslContext(
            KeyPair clientKp, X509Certificate clientCert,
            X509Certificate trustedCa) throws Exception {
        KeyStore ts = KeyStore.getInstance(KeyStore.getDefaultType());
        ts.load(null, null);
        ts.setCertificateEntry("ca", trustedCa);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(
            TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ts);
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("id", clientKp.getPrivate(), new char[0],
            new Certificate[]{clientCert});
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(
            KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, new char[0]);
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        return ctx;
    }

    private static CertificateCapturingTrustManager buildCapturingTrustManager()
            throws Exception {
        KeyStore ts = KeyStore.getInstance(KeyStore.getDefaultType());
        ts.load(null, null);
        ts.setCertificateEntry("public-ca", publicCaRootCert);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(
            TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(ts);
        X509TrustManager baseTm = null;
        for (TrustManager tm : tmf.getTrustManagers()) {
            if (tm instanceof X509TrustManager) {
                baseTm = (X509TrustManager) tm;
                break;
            }
        }
        return new CertificateCapturingTrustManager(baseTm);
    }

    private static HttpClient buildCapturingHttpClient(
            CertificateCapturingTrustManager capturingTm) throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");
        ks.load(null, null);
        ks.setKeyEntry("id", identityKeyPair.getPrivate(),
            new char[0], new Certificate[]{identityCert});
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(
            KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(ks, new char[0]);
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(kmf.getKeyManagers(), new TrustManager[]{capturingTm}, null);
        return HttpClient.newBuilder().sslContext(ctx).build();
    }

    private static String bytesToHex(byte[] bytes) {
        char[] hex = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            hex[i * 2] = "0123456789abcdef".charAt((bytes[i] >> 4) & 0x0F);
            hex[i * 2 + 1] = "0123456789abcdef".charAt(bytes[i] & 0x0F);
        }
        return new String(hex);
    }

    // --- Certificate generation helpers ---

    private static void generateCertificates() throws Exception {
        publicCaKeyPair = generateEcKeyPair();
        publicCaRootCert = generateSelfSignedCa(publicCaKeyPair, "CN=Test Public CA");
        serverKeyPair = generateEcKeyPair();
        serverCert = generateLeafCert(
            serverKeyPair, publicCaKeyPair, publicCaRootCert, "CN=localhost");
        idcaKeyPair = generateEcKeyPair();
        idcaRootCert = generateSelfSignedCa(idcaKeyPair, "CN=Test IDCA");
        identityKeyPair = generateEcKeyPair();
        identityCert = generateLeafCert(
            identityKeyPair, idcaKeyPair, idcaRootCert, "CN=test-agent");
        tlKeyPair = generateEcKeyPair();
    }

    private static void startMockServer() throws Exception {
        httpsServer = HttpsServer.create(new InetSocketAddress(0), 0);
        serverPort = httpsServer.getAddress().getPort();
        KeyStore serverKs = KeyStore.getInstance("PKCS12");
        serverKs.load(null, null);
        serverKs.setKeyEntry("server", serverKeyPair.getPrivate(), new char[0],
            new Certificate[]{serverCert, publicCaRootCert});
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(
            KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(serverKs, new char[0]);
        KeyStore trustKs = KeyStore.getInstance(KeyStore.getDefaultType());
        trustKs.load(null, null);
        trustKs.setCertificateEntry("idca-root", idcaRootCert);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(
            TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustKs);
        SSLContext serverCtx = SSLContext.getInstance("TLS");
        serverCtx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);
        httpsServer.setHttpsConfigurator(new HttpsConfigurator(serverCtx) {
            @Override
            public void configure(HttpsParameters params) {
                SSLParameters p = getSSLContext().getDefaultSSLParameters();
                p.setNeedClientAuth(true);
                params.setSSLParameters(p);
            }
        });
        httpsServer.createContext("/api/hello", exchange -> {
            String body = "{\"status\":\"ok\"}";
            exchange.getResponseHeaders().set("Content-Type", "application/json");
            exchange.sendResponseHeaders(200, body.length());
            try (OutputStream os = exchange.getResponseBody()) {
                os.write(body.getBytes());
            }
        });
        httpsServer.setExecutor(null);
        httpsServer.start();
    }

    private static KeyPair generateEcKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        return kpg.generateKeyPair();
    }

    private static X509Certificate generateSelfSignedCa(KeyPair keyPair, String dn) throws Exception {
        Instant now = Instant.now();
        X500Name issuer = new X500Name(dn);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
            issuer,
            BigInteger.valueOf(1),
            Date.from(now),
            Date.from(now.plus(365, ChronoUnit.DAYS)),
            issuer,
            keyPair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(keyPair.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    private static X509Certificate generateLeafCert(
            KeyPair leafKeyPair, KeyPair issuerKeyPair,
            X509Certificate issuerCert, String subjectDn) throws Exception {
        Instant now = Instant.now();
        X500Name issuer = new X500Name(issuerCert.getSubjectX500Principal().getName());
        X500Name subject = new X500Name(subjectDn);
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
            issuer,
            BigInteger.valueOf(System.nanoTime()),
            Date.from(now),
            Date.from(now.plus(30, ChronoUnit.DAYS)),
            subject,
            leafKeyPair.getPublic());
        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        // Add SAN for localhost so TLS hostname verification passes
        if (subjectDn.contains("localhost")) {
            GeneralNames sans = new GeneralNames(new GeneralName(GeneralName.dNSName, "localhost"));
            builder.addExtension(Extension.subjectAlternativeName, false, sans);
        }
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA").build(issuerKeyPair.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }
}
