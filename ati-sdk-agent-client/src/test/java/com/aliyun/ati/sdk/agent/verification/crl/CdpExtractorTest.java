package com.aliyun.ati.sdk.agent.verification.crl;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("CdpExtractor")
class CdpExtractorTest {

    @Test
    @DisplayName("reads CDP from leaf Identity Certificate")
    void readsCdpFromLeaf() throws Exception {
        CrlTestFixtures.TestCa ca = CrlTestFixtures.createTestCa("http://crl.example.test/leaf.crl");
        CrlTestFixtures.ClientCert client = CrlTestFixtures.createClientCert(
            ca, BigInteger.valueOf(42), "http://crl.example.test/leaf.crl");

        Optional<URI> cdp = CdpExtractor.extractFirstCdpUri(new X509Certificate[] {
            client.certificate(), ca.certificate()
        });

        assertThat(cdp).contains(URI.create("http://crl.example.test/leaf.crl"));
    }

    @Test
    @DisplayName("falls back to issuing CA CDP when leaf has none")
    void fallsBackToIssuerCdp() throws Exception {
        String issuerCrlUrl = "http://crl.example.test/issuer.crl";
        CrlTestFixtures.TestCa ca = CrlTestFixtures.createTestCa(issuerCrlUrl);
        CrlTestFixtures.ClientCert client = CrlTestFixtures.createClientCert(ca, BigInteger.valueOf(7), null);

        Optional<URI> cdp = CdpExtractor.extractFirstCdpUri(new X509Certificate[] {
            client.certificate(), ca.certificate()
        });

        assertThat(cdp).contains(URI.create(issuerCrlUrl));
    }

    @Test
    @DisplayName("returns empty when chain has no CDP")
    void skipsWhenNoCdpOnChain() throws Exception {
        CrlTestFixtures.TestCa ca = CrlTestFixtures.createTestCa(null);
        CrlTestFixtures.ClientCert client = CrlTestFixtures.createClientCert(ca, BigInteger.valueOf(9), null);

        Optional<URI> cdp = CdpExtractor.extractFirstCdpUri(new X509Certificate[] {
            client.certificate(), ca.certificate()
        });

        assertThat(cdp).isEmpty();
    }

    @Test
    @DisplayName("prefers leaf CDP over issuer CDP")
    void prefersLeafOverIssuer() throws Exception {
        CrlTestFixtures.TestCa ca = CrlTestFixtures.createTestCa("http://crl.example.test/issuer.crl");
        CrlTestFixtures.ClientCert client = CrlTestFixtures.createClientCert(
            ca, BigInteger.valueOf(11), "http://crl.example.test/leaf.crl");

        Optional<URI> cdp = CdpExtractor.extractFirstCdpUri(new X509Certificate[] {
            client.certificate(), ca.certificate()
        });

        assertThat(cdp).contains(URI.create("http://crl.example.test/leaf.crl"));
    }
}
