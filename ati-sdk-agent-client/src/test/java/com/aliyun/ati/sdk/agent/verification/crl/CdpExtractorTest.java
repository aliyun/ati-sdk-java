package com.aliyun.ati.sdk.agent.verification.crl;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.net.URI;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("CdpExtractor")
class CdpExtractorTest {

    @Test
    @DisplayName("reads CDP from leaf Identity Certificate")
    void readsCdpFromLeaf() throws Exception {
        CrlTestFixtures.TestCa ca = CrlTestFixtures.createTestCa("http://crl.example.test/leaf.crl");
        CrlTestFixtures.ClientCert client = CrlTestFixtures.createClientCert(
            ca, BigInteger.valueOf(42), "http://crl.example.test/leaf.crl");

        CdpExtractor.CdpLookupResult result = CdpExtractor.resolveFirstCdpUri(new X509Certificate[] {
            client.certificate(), ca.certificate()
        });

        assertThat(result.isFound()).isTrue();
        assertThat(result.cdpUri()).isEqualTo(URI.create("http://crl.example.test/leaf.crl"));
    }

    @Test
    @DisplayName("falls back to issuing CA CDP when leaf has none")
    void fallsBackToIssuerCdp() throws Exception {
        String issuerCrlUrl = "http://crl.example.test/issuer.crl";
        CrlTestFixtures.TestCa ca = CrlTestFixtures.createTestCa(issuerCrlUrl);
        CrlTestFixtures.ClientCert client = CrlTestFixtures.createClientCert(ca, BigInteger.valueOf(7), null);

        CdpExtractor.CdpLookupResult result = CdpExtractor.resolveFirstCdpUri(new X509Certificate[] {
            client.certificate(), ca.certificate()
        });

        assertThat(result.isFound()).isTrue();
        assertThat(result.cdpUri()).isEqualTo(URI.create(issuerCrlUrl));
    }

    @Test
    @DisplayName("returns skipped when chain has no CDP")
    void skipsWhenNoCdpOnChain() throws Exception {
        CrlTestFixtures.TestCa ca = CrlTestFixtures.createTestCa(null);
        CrlTestFixtures.ClientCert client = CrlTestFixtures.createClientCert(ca, BigInteger.valueOf(9), null);

        CdpExtractor.CdpLookupResult result = CdpExtractor.resolveFirstCdpUri(new X509Certificate[] {
            client.certificate(), ca.certificate()
        });

        assertThat(result.isSkipped()).isTrue();
    }

    @Test
    @DisplayName("prefers leaf CDP over issuer CDP")
    void prefersLeafOverIssuer() throws Exception {
        CrlTestFixtures.TestCa ca = CrlTestFixtures.createTestCa("http://crl.example.test/issuer.crl");
        CrlTestFixtures.ClientCert client = CrlTestFixtures.createClientCert(
            ca, BigInteger.valueOf(11), "http://crl.example.test/leaf.crl");

        CdpExtractor.CdpLookupResult result = CdpExtractor.resolveFirstCdpUri(new X509Certificate[] {
            client.certificate(), ca.certificate()
        });

        assertThat(result.isFound()).isTrue();
        assertThat(result.cdpUri()).isEqualTo(URI.create("http://crl.example.test/leaf.crl"));
    }

    @Test
    @DisplayName("fail-closed when CDP extension cannot be parsed")
    void failsWhenCdpExtensionIsMalformed() throws Exception {
        CrlTestFixtures.TestCa ca = CrlTestFixtures.createTestCa(null);
        CrlTestFixtures.ClientCert client = CrlTestFixtures.createClientCertWithMalformedCdpExtension(
            ca, BigInteger.valueOf(12));

        CdpExtractor.CdpLookupResult result = CdpExtractor.resolveFirstCdpUri(new X509Certificate[] {
            client.certificate(), ca.certificate()
        });

        assertThat(result.isFailed()).isTrue();
        assertThat(result.failureMessage()).contains("Failed to parse CDP extension");
    }

    @Test
    @DisplayName("fail-closed when CDP extension has no HTTP(S) URI")
    void failsWhenCdpHasOnlyNonHttpUri() throws Exception {
        CrlTestFixtures.TestCa ca = CrlTestFixtures.createTestCa(null);
        CrlTestFixtures.ClientCert client = CrlTestFixtures.createClientCertWithLdapOnlyCdp(
            ca, BigInteger.valueOf(13));

        CdpExtractor.CdpLookupResult result = CdpExtractor.resolveFirstCdpUri(new X509Certificate[] {
            client.certificate(), ca.certificate()
        });

        assertThat(result.isFailed()).isTrue();
        assertThat(result.failureMessage()).contains("no HTTP(S) URI");
    }

    @Test
    @DisplayName("findIssuingCa matches issuer DN instead of chain position")
    void findIssuingCaMatchesIssuerDn() throws Exception {
        CrlTestFixtures.TestCa ca = CrlTestFixtures.createTestCa("http://crl.example.test/issuer.crl");
        CrlTestFixtures.TestCa unrelatedCa = CrlTestFixtures.createTestCa(null, "Unrelated Intermediate CA");
        CrlTestFixtures.ClientCert client = CrlTestFixtures.createClientCert(ca, BigInteger.valueOf(14), null);

        assertThat(CdpExtractor.findIssuingCa(
            client.certificate(),
            new X509Certificate[] { client.certificate(), unrelatedCa.certificate(), ca.certificate() }
        )).contains(ca.certificate());

        assertThat(CdpExtractor.findIssuingCa(
            client.certificate(),
            new X509Certificate[] { client.certificate(), unrelatedCa.certificate() }
        )).isEmpty();
    }
}