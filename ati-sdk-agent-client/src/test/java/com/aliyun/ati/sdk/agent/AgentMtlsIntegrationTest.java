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
import java.security.cert.Certificate;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManagerFactory;

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

/**
 * Integration test validating the full mTLS connection flow between two ATI agents.
 *
 * <p>Uses the dual-cert model:
 * <ul>
 *   <li>"Public CA" chain: self-signed root -> server cert (for mock server TLS)</li>
 *   <li>IDCA chain: self-signed root -> identity cert (for mTLS client auth)</li>
 * </ul>
 *
 * <p>The mock HTTPS server requires client authentication ({@code needClientAuth=true}),
 * trusting only identity certs signed by the IDCA root.
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
        // Build client SSLContext:
        // TrustManager: trust the self-signed "public CA" root
        // KeyManager: identity cert + key (IDCA signed)
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null, null);
        trustStore.setCertificateEntry("public-ca", publicCaRootCert);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        keyStore.setKeyEntry("identity", identityKeyPair.getPrivate(), new char[0],
            new Certificate[]{identityCert});
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, new char[0]);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        HttpClient httpClient = HttpClient.newBuilder()
            .sslContext(sslContext)
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://localhost:" + serverPort + "/api/hello"))
            .GET()
            .build();

        HttpResponse<String> response = httpClient.send(request,
            HttpResponse.BodyHandlers.ofString());

        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.body()).contains("ok");
    }

    @Test
    void shouldRejectClientWithoutIdentityCert() throws Exception {
        // Client without identity cert (no KeyManager)
        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null, null);
        trustStore.setCertificateEntry("public-ca", publicCaRootCert);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, tmf.getTrustManagers(), null);

        HttpClient httpClient = HttpClient.newBuilder()
            .sslContext(sslContext)
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://localhost:" + serverPort + "/api/hello"))
            .GET()
            .build();

        // Should fail because server requires client cert (needClientAuth)
        assertThatThrownBy(() -> httpClient.send(request, HttpResponse.BodyHandlers.ofString()))
            .isInstanceOf(Exception.class);
    }

    @Test
    void shouldRejectClientWithWrongCaCert() throws Exception {
        // Client with identity cert signed by a different (wrong) CA
        KeyPair wrongCaKeyPair = generateEcKeyPair();
        X509Certificate wrongCaRoot = generateSelfSignedCa(wrongCaKeyPair, "CN=Wrong CA");
        KeyPair wrongIdentityKeyPair = generateEcKeyPair();
        X509Certificate wrongIdentityCert = generateLeafCert(
            wrongIdentityKeyPair, wrongCaKeyPair, wrongCaRoot, "CN=wrong-agent");

        KeyStore trustStore = KeyStore.getInstance(KeyStore.getDefaultType());
        trustStore.load(null, null);
        trustStore.setCertificateEntry("public-ca", publicCaRootCert);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustStore);

        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        keyStore.load(null, null);
        keyStore.setKeyEntry("identity", wrongIdentityKeyPair.getPrivate(), new char[0],
            new Certificate[]{wrongIdentityCert});
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(keyStore, new char[0]);

        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        HttpClient httpClient = HttpClient.newBuilder()
            .sslContext(sslContext)
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://localhost:" + serverPort + "/api/hello"))
            .GET()
            .build();

        // Should fail because server doesn't trust this CA
        assertThatThrownBy(() -> httpClient.send(request, HttpResponse.BodyHandlers.ofString()))
            .isInstanceOf(Exception.class);
    }

    // --- Certificate generation helpers (using BouncyCastle) ---

    private static void generateCertificates() throws Exception {
        // Public CA chain (for server TLS)
        publicCaKeyPair = generateEcKeyPair();
        publicCaRootCert = generateSelfSignedCa(publicCaKeyPair, "CN=Test Public CA");
        serverKeyPair = generateEcKeyPair();
        serverCert = generateLeafCert(serverKeyPair, publicCaKeyPair, publicCaRootCert, "CN=localhost");

        // IDCA chain (for mTLS identity)
        idcaKeyPair = generateEcKeyPair();
        idcaRootCert = generateSelfSignedCa(idcaKeyPair, "CN=Test IDCA");
        identityKeyPair = generateEcKeyPair();
        identityCert = generateLeafCert(identityKeyPair, idcaKeyPair, idcaRootCert, "CN=test-agent");
    }

    private static void startMockServer() throws Exception {
        httpsServer = HttpsServer.create(new InetSocketAddress(0), 0);
        serverPort = httpsServer.getAddress().getPort();

        // Server SSLContext:
        // KeyManager: server cert (public CA signed)
        // TrustManager: IDCA root (verify client identity certs)
        KeyStore serverKs = KeyStore.getInstance("PKCS12");
        serverKs.load(null, null);
        serverKs.setKeyEntry("server", serverKeyPair.getPrivate(), new char[0],
            new Certificate[]{serverCert, publicCaRootCert});
        KeyManagerFactory kmf = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        kmf.init(serverKs, new char[0]);

        KeyStore trustKs = KeyStore.getInstance(KeyStore.getDefaultType());
        trustKs.load(null, null);
        trustKs.setCertificateEntry("idca-root", idcaRootCert);
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        tmf.init(trustKs);

        SSLContext serverSslContext = SSLContext.getInstance("TLS");
        serverSslContext.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

        httpsServer.setHttpsConfigurator(new HttpsConfigurator(serverSslContext) {
            @Override
            public void configure(HttpsParameters params) {
                SSLParameters sslParams = getSSLContext().getDefaultSSLParameters();
                sslParams.setNeedClientAuth(true);
                params.setSSLParameters(sslParams);
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
