package com.aliyun.ati.sdk.spring;

import com.aliyun.ati.sdk.agent.VerificationPolicy;
import com.aliyun.ati.sdk.agent.server.ClientRequestVerificationResult;
import com.aliyun.ati.sdk.agent.server.DefaultClientRequestVerifier;
import com.aliyun.ati.sdk.agent.verification.crl.CrlFetcher;
import com.aliyun.ati.sdk.agent.verification.crl.CrlRevocationChecker;
import com.aliyun.ati.sdk.agent.verification.crl.CrlTestFixtures;
import com.aliyun.ati.sdk.agent.verification.crl.DefaultCrlHttpClient;
import com.aliyun.ati.sdk.crypto.CertificateUtils;
import com.aliyun.ati.sdk.crypto.KeyPairManager;
import com.aliyun.ati.sdk.transparency.verification.BadgeVerificationService;
import com.aliyun.ati.sdk.transparency.verification.ClientVerificationResult;
import com.aliyun.ati.sdk.transparency.verification.VerificationStatus;
import com.github.tomakehurst.wiremock.WireMockServer;
import jakarta.servlet.http.HttpServlet;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.Ssl;
import org.springframework.boot.web.server.WebServer;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Set;
import javax.net.ssl.SSLContext;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.configureFor;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * AC2 end-to-end: CRL passes at TLS layer, then Badge (Client Verification) still applies.
 */
@DisplayName("IDCA CRL + Badge dual-track integration")
class AtiIdcaCrlBadgeDualTrackIntegrationTest {

    private static final String ATI_URI_SAN = "ati://v1.dual-track.example.com";
    private static final KeyPairManager KEY_PAIR_MANAGER = new KeyPairManager();
    private static final BigInteger VALID_SERIAL = BigInteger.valueOf(8201);
    private static final WireMockServer WIRE_MOCK = new WireMockServer(wireMockConfig().dynamicPort());

    private static Path materialDir;
    private static CrlTestFixtures.TestCa issuingCa;
    private static CrlTestFixtures.ClientCert validClient;
    private static X509Certificate serverCertificate;

    @BeforeAll
    static void setUpFixtures() throws Exception {
        WIRE_MOCK.start();
        configureFor("localhost", WIRE_MOCK.port());

        materialDir = Files.createTempDirectory("ati-crl-badge-");
        String crlUrl = "http://localhost:" + WIRE_MOCK.port() + "/crl";
        issuingCa = CrlTestFixtures.createTestCa(crlUrl);
        validClient = CrlTestFixtures.createClientCert(issuingCa, VALID_SERIAL, crlUrl, ATI_URI_SAN);

        KeyPair serverKeyPair = KeyPairGenerator.getInstance("EC").generateKeyPair();
        serverCertificate = createServerCertificate(serverKeyPair);

        writePem(materialDir.resolve("idca-trust.pem"), CertificateUtils.toPem(issuingCa.certificate()));
        writePem(materialDir.resolve("server.pem"), CertificateUtils.toPem(serverCertificate));
        writePem(materialDir.resolve("server.key"), KEY_PAIR_MANAGER.getPrivateKeyAsPem(serverKeyPair));

        WIRE_MOCK.stubFor(get(urlEqualTo("/crl"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/pkix-crl")
                .withBody(CrlTestFixtures.createCrlBytes(
                    issuingCa,
                    Instant.now().plus(1, ChronoUnit.DAYS),
                    Set.of()))));
    }

    @AfterAll
    static void tearDownFixtures() {
        WIRE_MOCK.stop();
    }

    @Test
    @DisplayName("CRL passes at TLS then Registration Revocation rejects at Client Verification")
    void crlPassesThenBadgeRejectsAtApplicationLayer() throws Exception {
        BadgeVerificationService badgeService = mock(BadgeVerificationService.class);
        when(badgeService.verifyClient(validClient.certificate()))
            .thenReturn(ClientVerificationResult.builder()
                .status(VerificationStatus.REGISTRATION_INVALID)
                .warningMessage("Registration status: REVOKED")
                .build());

        DefaultClientRequestVerifier verifier = DefaultClientRequestVerifier.builder()
            .badgeVerificationService(badgeService)
            .build();

        try (TomcatHarness harness = startTomcatServer(verifier, VerificationPolicy.ENHANCED)) {
            HttpClient client = createMtlsClient(validClient, issuingCa);

            HttpResponse<String> response = sendRequest(client, harness.port());

            assertThat(response.statusCode()).isEqualTo(403);
            assertThat(response.body()).contains("REVOKED");
        }
    }

    @Test
    @DisplayName("CRL passes at TLS and valid Badge allows request through Client Verification")
    void crlPassesThenBadgeAllowsAtApplicationLayer() throws Exception {
        BadgeVerificationService badgeService = mock(BadgeVerificationService.class);
        when(badgeService.verifyClient(validClient.certificate()))
            .thenReturn(ClientVerificationResult.builder()
                .status(VerificationStatus.VERIFIED)
                .build());

        DefaultClientRequestVerifier verifier = DefaultClientRequestVerifier.builder()
            .badgeVerificationService(badgeService)
            .build();

        try (TomcatHarness harness = startTomcatServer(verifier, VerificationPolicy.ENHANCED)) {
            HttpClient client = createMtlsClient(validClient, issuingCa);

            HttpResponse<String> response = sendRequest(client, harness.port());

            assertThat(response.statusCode()).isEqualTo(200);
        }
    }

    private static TomcatHarness startTomcatServer(
            DefaultClientRequestVerifier verifier,
            VerificationPolicy policy) {
        CrlRevocationChecker crlRevocationChecker =
            new CrlRevocationChecker(new CrlFetcher(new DefaultCrlHttpClient()));

        TomcatServletWebServerFactory factory = new TomcatServletWebServerFactory();
        factory.setPort(0);

        Ssl ssl = new Ssl();
        ssl.setEnabled(true);
        ssl.setCertificate(materialDir.resolve("server.pem").toString());
        ssl.setCertificatePrivateKey(materialDir.resolve("server.key").toString());
        ssl.setTrustCertificate(materialDir.resolve("idca-trust.pem").toString());
        ssl.setClientAuth(Ssl.ClientAuth.NEED);
        ssl.setEnabledProtocols(new String[] { "TLSv1.2" });
        factory.setSsl(ssl);
        factory.addConnectorCustomizers(new AtiIdcaCrlTomcatCustomizer(crlRevocationChecker));

        WebServer webServer = factory.getWebServer(context -> context.addServlet("verify",
            new ClientVerificationServlet(verifier, policy)).addMapping("/*"));
        webServer.start();
        return new TomcatHarness(webServer, webServer.getPort());
    }

    private static HttpResponse<String> sendRequest(HttpClient client, int port) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://localhost:" + port + "/"))
            .timeout(java.time.Duration.ofSeconds(5))
            .GET()
            .build();
        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }

    private static HttpClient createMtlsClient(
            CrlTestFixtures.ClientCert clientCert,
            CrlTestFixtures.TestCa ca)
            throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        char[] password = "changeit".toCharArray();
        keyStore.setKeyEntry(
            "client",
            clientCert.keyPair().getPrivate(),
            password,
            new X509Certificate[] { clientCert.certificate(), ca.certificate() }
        );

        KeyStore trustStore = KeyStore.getInstance("PKCS12");
        trustStore.load(null, null);
        trustStore.setCertificateEntry("server", serverCertificate);

        javax.net.ssl.KeyManagerFactory keyManagerFactory =
            javax.net.ssl.KeyManagerFactory.getInstance(javax.net.ssl.KeyManagerFactory.getDefaultAlgorithm());
        keyManagerFactory.init(keyStore, password);

        javax.net.ssl.TrustManagerFactory trustManagerFactory =
            javax.net.ssl.TrustManagerFactory.getInstance(javax.net.ssl.TrustManagerFactory.getDefaultAlgorithm());
        trustManagerFactory.init(trustStore);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(keyManagerFactory.getKeyManagers(), trustManagerFactory.getTrustManagers(), null);

        return HttpClient.newBuilder()
            .sslContext(sslContext)
            .connectTimeout(java.time.Duration.ofSeconds(5))
            .build();
    }

    private static X509Certificate createServerCertificate(KeyPair serverKeyPair) throws Exception {
        X500Name subject = new X500Name("CN=localhost, O=Test, C=CN");
        Instant now = Instant.now();
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
            subject,
            BigInteger.valueOf(4343),
            Date.from(now.minus(1, ChronoUnit.HOURS)),
            Date.from(now.plus(30, ChronoUnit.DAYS)),
            subject,
            serverKeyPair.getPublic()
        );
        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
            .build(serverKeyPair.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(certBuilder.build(signer));
    }

    private static void writePem(Path path, String pem) throws IOException {
        Files.writeString(path, pem);
    }

    private static final class ClientVerificationServlet extends HttpServlet {
        private final DefaultClientRequestVerifier verifier;
        private final VerificationPolicy policy;

        private ClientVerificationServlet(DefaultClientRequestVerifier verifier, VerificationPolicy policy) {
            this.verifier = verifier;
            this.policy = policy;
        }

        @Override
        protected void doGet(HttpServletRequest req, HttpServletResponse resp) throws IOException {
            X509Certificate[] certs = (X509Certificate[])
                req.getAttribute("jakarta.servlet.request.X509Certificate");
            if (certs == null || certs.length == 0) {
                resp.sendError(HttpServletResponse.SC_UNAUTHORIZED, "Client certificate required");
                return;
            }

            ClientRequestVerificationResult result = verifier.verify(certs[0], policy);
            if (!result.verified()) {
                resp.sendError(HttpServletResponse.SC_FORBIDDEN, String.join(", ", result.errors()));
                return;
            }
            resp.setStatus(HttpServletResponse.SC_OK);
            resp.getWriter().write("verified");
        }
    }

    private static final class TomcatHarness implements AutoCloseable {
        private final WebServer webServer;
        private final int port;

        private TomcatHarness(WebServer webServer, int port) {
            this.webServer = webServer;
            this.port = port;
        }

        int port() {
            return port;
        }

        @Override
        public void close() {
            webServer.stop();
        }
    }
}
