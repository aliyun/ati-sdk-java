package com.aliyun.ati.sdk.spring;

import com.aliyun.ati.sdk.agent.verification.crl.CrlFetcher;
import com.aliyun.ati.sdk.agent.verification.crl.CrlRevocationChecker;
import com.aliyun.ati.sdk.agent.verification.crl.CrlTestFixtures;
import com.aliyun.ati.sdk.agent.verification.crl.DefaultCrlHttpClient;
import com.aliyun.ati.sdk.crypto.CertificateUtils;
import com.aliyun.ati.sdk.crypto.KeyPairManager;
import com.github.tomakehurst.wiremock.WireMockServer;
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
import javax.net.ssl.SSLHandshakeException;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.configureFor;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("IDCA CRL mTLS integration")
class AtiIdcaCrlMtlsIntegrationTest {

    private static final KeyPairManager KEY_PAIR_MANAGER = new KeyPairManager();
    private static final BigInteger REVOKED_SERIAL = BigInteger.valueOf(7101);
    private static final BigInteger VALID_SERIAL = BigInteger.valueOf(7102);
    private static final WireMockServer WIRE_MOCK = new WireMockServer(wireMockConfig().dynamicPort());

    private static Path materialDir;
    private static CrlTestFixtures.TestCa issuingCa;
    private static CrlTestFixtures.ClientCert revokedClient;
    private static CrlTestFixtures.ClientCert validClient;
    private static X509Certificate serverCertificate;

    @BeforeAll
    static void setUpFixtures() throws Exception {
        WIRE_MOCK.start();
        configureFor("localhost", WIRE_MOCK.port());

        materialDir = Files.createTempDirectory("ati-crl-mtls-");
        String crlUrl = "http://localhost:" + WIRE_MOCK.port() + "/crl";
        issuingCa = CrlTestFixtures.createTestCa(crlUrl);
        revokedClient = CrlTestFixtures.createClientCert(issuingCa, REVOKED_SERIAL, crlUrl);
        validClient = CrlTestFixtures.createClientCert(issuingCa, VALID_SERIAL, crlUrl);

        KeyPair serverKeyPair = KeyPairGenerator.getInstance("EC").generateKeyPair();
        serverCertificate = createServerCertificate(serverKeyPair);

        writePem(materialDir.resolve("idca-trust.pem"), CertificateUtils.toPem(issuingCa.certificate()));
        writePem(materialDir.resolve("server.pem"), CertificateUtils.toPem(serverCertificate));
        writePem(materialDir.resolve("server.key"), KEY_PAIR_MANAGER.getPrivateKeyAsPem(serverKeyPair));

        stubCrl(Set.of(REVOKED_SERIAL));
    }

    @AfterAll
    static void tearDownFixtures() {
        WIRE_MOCK.stop();
    }

    @Test
    @DisplayName("rejects mTLS handshake when client serial is on CRL")
    void rejectsRevokedClientDuringMtlsHandshake() throws Exception {
        try (TomcatHarness harness = startTomcatServer(materialDir.resolve("idca-trust.pem"))) {
            HttpClient client = createMtlsClient(revokedClient, issuingCa);

            assertThatThrownBy(() -> sendRequest(client, harness.port()))
                .rootCause()
                .isInstanceOf(SSLHandshakeException.class);
        }
    }

    @Test
    @DisplayName("allows mTLS handshake when client serial is not on CRL")
    void allowsNonRevokedClientDuringMtlsHandshake() throws Exception {
        try (TomcatHarness harness = startTomcatServer(materialDir.resolve("idca-trust.pem"))) {
            HttpClient client = createMtlsClient(validClient, issuingCa);

            HttpResponse<Void> response = sendRequest(client, harness.port());

            assertThat(response.statusCode()).isBetween(200, 499);
        }
    }

    @Test
    @DisplayName("allows mTLS handshake when certificate chain has no CDP")
    void allowsClientWhenNoCdpOnChain() throws Exception {
        CrlTestFixtures.TestCa caWithoutCdp = CrlTestFixtures.createTestCa(null);
        CrlTestFixtures.ClientCert clientWithoutCdp =
            CrlTestFixtures.createClientCert(caWithoutCdp, BigInteger.valueOf(7201), null);
        Path trustPem = materialDir.resolve("idca-trust-no-cdp.pem");
        writePem(trustPem, CertificateUtils.toPem(caWithoutCdp.certificate()));

        try (TomcatHarness harness = startTomcatServer(trustPem)) {
            HttpClient client = createMtlsClient(clientWithoutCdp, caWithoutCdp);

            HttpResponse<Void> response = sendRequest(client, harness.port());

            assertThat(response.statusCode()).isBetween(200, 499);
        }
    }

    private static TomcatHarness startTomcatServer(Path idcaTrustPem) {
        CrlRevocationChecker crlRevocationChecker =
            new CrlRevocationChecker(new CrlFetcher(new DefaultCrlHttpClient()));

        TomcatServletWebServerFactory factory = new TomcatServletWebServerFactory();
        factory.setPort(0);

        Ssl ssl = new Ssl();
        ssl.setEnabled(true);
        ssl.setCertificate(materialDir.resolve("server.pem").toString());
        ssl.setCertificatePrivateKey(materialDir.resolve("server.key").toString());
        ssl.setTrustCertificate(idcaTrustPem.toString());
        ssl.setClientAuth(Ssl.ClientAuth.NEED);
        ssl.setEnabledProtocols(new String[] { "TLSv1.2" });
        factory.setSsl(ssl);
        factory.addConnectorCustomizers(new AtiIdcaCrlTomcatCustomizer(crlRevocationChecker));

        WebServer webServer = factory.getWebServer(context -> { });
        webServer.start();
        return new TomcatHarness(webServer, webServer.getPort());
    }

    private static void stubCrl(Set<BigInteger> revokedSerials) throws Exception {
        WIRE_MOCK.stubFor(get(urlEqualTo("/crl"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/pkix-crl")
                .withBody(CrlTestFixtures.createCrlBytes(
                    issuingCa,
                    Instant.now().plus(1, ChronoUnit.DAYS),
                    revokedSerials))));
    }

    private static HttpResponse<Void> sendRequest(HttpClient client, int port) throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://localhost:" + port + "/"))
            .timeout(java.time.Duration.ofSeconds(5))
            .GET()
            .build();
        return client.send(request, HttpResponse.BodyHandlers.discarding());
    }

    private static HttpClient createMtlsClient(
            CrlTestFixtures.ClientCert clientCert,
            CrlTestFixtures.TestCa issuingCa)
            throws Exception {
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        char[] password = "changeit".toCharArray();
        keyStore.setKeyEntry(
            "client",
            clientCert.keyPair().getPrivate(),
            password,
            new X509Certificate[] { clientCert.certificate(), issuingCa.certificate() }
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
            BigInteger.valueOf(4242),
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
