package com.aliyun.ati.sdk.agent.verification.crl;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.math.BigInteger;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import static org.assertj.core.api.Assertions.assertThat;

@DisplayName("CrlRevocationChecker")
class CrlRevocationCheckerTest {

    private CrlTestFixtures.TestCa ca;
    private Map<URI, byte[]> crlResponses;
    private CrlRevocationChecker checker;

    @BeforeEach
    void setUp() throws Exception {
        ca = CrlTestFixtures.createTestCa("http://crl.example.test/revocation.crl");
        crlResponses = new ConcurrentHashMap<>();
        CrlHttpClient httpClient = uri -> {
            byte[] bytes = crlResponses.get(uri);
            if (bytes == null) {
                throw new IOException("CRL not found for " + uri);
            }
            return bytes;
        };
        checker = new CrlRevocationChecker(new CrlFetcher(httpClient));
    }

    @Test
    @DisplayName("skips CRL when chain has no CDP")
    void skipsWhenNoCdp() throws Exception {
        CrlTestFixtures.TestCa caWithoutCdp = CrlTestFixtures.createTestCa(null);
        CrlTestFixtures.ClientCert client = CrlTestFixtures.createClientCert(
            caWithoutCdp, BigInteger.valueOf(1), null);

        CrlRevocationResult result = checker.check(
            client.certificate(),
            new X509Certificate[] { client.certificate(), caWithoutCdp.certificate() }
        );

        assertThat(result.status()).isEqualTo(CrlRevocationResult.Status.SKIPPED);
        assertThat(result.shouldRejectConnection()).isFalse();
    }

    @Test
    @DisplayName("rejects revoked serial (Certificate Revocation)")
    void rejectsRevokedSerial() throws Exception {
        BigInteger serial = BigInteger.valueOf(9001);
        CrlTestFixtures.ClientCert client = CrlTestFixtures.createClientCert(
            ca, serial, "http://crl.example.test/revocation.crl");
        URI cdpUri = URI.create("http://crl.example.test/revocation.crl");
        crlResponses.put(cdpUri, CrlTestFixtures.createCrlBytes(
            ca, Instant.now().plus(1, ChronoUnit.DAYS), Set.of(serial)));

        CrlRevocationResult result = checker.check(
            client.certificate(),
            new X509Certificate[] { client.certificate(), ca.certificate() }
        );

        assertThat(result.status()).isEqualTo(CrlRevocationResult.Status.REVOKED);
        assertThat(result.shouldRejectConnection()).isTrue();
    }

    @Test
    @DisplayName("passes when serial is not on CRL")
    void passesWhenSerialNotRevoked() throws Exception {
        BigInteger serial = BigInteger.valueOf(9002);
        CrlTestFixtures.ClientCert client = CrlTestFixtures.createClientCert(
            ca, serial, "http://crl.example.test/revocation.crl");
        URI cdpUri = URI.create("http://crl.example.test/revocation.crl");
        crlResponses.put(cdpUri, CrlTestFixtures.createCrlBytes(
            ca, Instant.now().plus(1, ChronoUnit.DAYS), Set.of(BigInteger.valueOf(9999))));

        CrlRevocationResult result = checker.check(
            client.certificate(),
            new X509Certificate[] { client.certificate(), ca.certificate() }
        );

        assertThat(result.status()).isEqualTo(CrlRevocationResult.Status.PASSED);
        assertThat(result.shouldRejectConnection()).isFalse();
    }

    @Test
    @DisplayName("fail-closed when CRL fetch fails")
    void failClosedOnFetchFailure() throws Exception {
        CrlTestFixtures.ClientCert client = CrlTestFixtures.createClientCert(
            ca, BigInteger.valueOf(9003), "http://crl.example.test/unreachable.crl");

        CrlRevocationResult result = checker.check(
            client.certificate(),
            new X509Certificate[] { client.certificate(), ca.certificate() }
        );

        assertThat(result.status()).isEqualTo(CrlRevocationResult.Status.FAILED);
        assertThat(result.shouldRejectConnection()).isTrue();
    }

    @Test
    @DisplayName("fail-closed when CRL signature is invalid")
    void failClosedOnInvalidSignature() throws Exception {
        CrlTestFixtures.TestCa otherCa = CrlTestFixtures.createTestCa("http://crl.example.test/bad-sig.crl");
        BigInteger serial = BigInteger.valueOf(9004);
        CrlTestFixtures.ClientCert client = CrlTestFixtures.createClientCert(
            ca, serial, "http://crl.example.test/bad-sig.crl");
        URI cdpUri = URI.create("http://crl.example.test/bad-sig.crl");
        crlResponses.put(cdpUri, CrlTestFixtures.createCrlBytes(
            otherCa, Instant.now().plus(1, ChronoUnit.DAYS), Set.of()));

        CrlRevocationResult result = checker.check(
            client.certificate(),
            new X509Certificate[] { client.certificate(), ca.certificate() }
        );

        assertThat(result.status()).isEqualTo(CrlRevocationResult.Status.FAILED);
        assertThat(result.shouldRejectConnection()).isTrue();
    }

    @Test
    @DisplayName("reads CDP from issuing CA when leaf has none")
    void usesIssuerCdpFallback() throws Exception {
        BigInteger serial = BigInteger.valueOf(9005);
        CrlTestFixtures.ClientCert client = CrlTestFixtures.createClientCert(ca, serial, null);
        URI cdpUri = URI.create("http://crl.example.test/revocation.crl");
        crlResponses.put(cdpUri, CrlTestFixtures.createCrlBytes(
            ca, Instant.now().plus(1, ChronoUnit.DAYS), Set.of()));

        CrlRevocationResult result = checker.check(
            client.certificate(),
            new X509Certificate[] { client.certificate(), ca.certificate() }
        );

        assertThat(result.status()).isEqualTo(CrlRevocationResult.Status.PASSED);
    }
}
