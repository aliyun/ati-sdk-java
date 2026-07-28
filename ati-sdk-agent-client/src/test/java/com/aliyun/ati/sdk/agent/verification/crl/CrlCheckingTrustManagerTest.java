package com.aliyun.ati.sdk.agent.verification.crl;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;

import java.math.BigInteger;
import java.net.URI;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;

import static org.assertj.core.api.Assertions.assertThatCode;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.verify;

@ExtendWith(MockitoExtension.class)
@DisplayName("CrlCheckingTrustManager")
class CrlCheckingTrustManagerTest {

    private CrlTestFixtures.TestCa ca;
    private Map<URI, byte[]> crlResponses;
    private CrlCheckingTrustManager trustManager;

    @BeforeEach
    void setUp() throws Exception {
        ca = CrlTestFixtures.createTestCa("http://crl.example.test/revocation.crl");
        crlResponses = new ConcurrentHashMap<>();
        CrlHttpClient httpClient = uri -> {
            byte[] bytes = crlResponses.get(uri);
            if (bytes == null) {
                throw new java.io.IOException("CRL not found for " + uri);
            }
            return bytes;
        };
        CrlRevocationChecker checker = new CrlRevocationChecker(new CrlFetcher(httpClient));
        trustManager = new CrlCheckingTrustManager(new PermissiveTrustManager(), checker);
    }

    @Test
    @DisplayName("rejects client certificate when serial is on CRL")
    void rejectsRevokedClientCertificate() throws Exception {
        BigInteger serial = BigInteger.valueOf(42);
        CrlTestFixtures.ClientCert client = CrlTestFixtures.createClientCert(
            ca, serial, "http://crl.example.test/revocation.crl");
        URI cdpUri = URI.create("http://crl.example.test/revocation.crl");
        crlResponses.put(cdpUri, CrlTestFixtures.createCrlBytes(
            ca, Instant.now().plus(1, ChronoUnit.DAYS), Set.of(serial)));

        X509Certificate[] chain = new X509Certificate[] { client.certificate(), ca.certificate() };

        assertThatThrownBy(() -> trustManager.checkClientTrusted(chain, "RSA"))
            .isInstanceOf(CertificateException.class)
            .hasMessageContaining("revoked");
    }

    @Test
    @DisplayName("accepts client certificate when serial is not on CRL")
    void acceptsNonRevokedClientCertificate() throws Exception {
        BigInteger serial = BigInteger.valueOf(43);
        CrlTestFixtures.ClientCert client = CrlTestFixtures.createClientCert(
            ca, serial, "http://crl.example.test/revocation.crl");
        URI cdpUri = URI.create("http://crl.example.test/revocation.crl");
        crlResponses.put(cdpUri, CrlTestFixtures.createCrlBytes(
            ca, Instant.now().plus(1, ChronoUnit.DAYS), Set.of(BigInteger.valueOf(999))));

        X509Certificate[] chain = new X509Certificate[] { client.certificate(), ca.certificate() };

        assertThatCode(() -> trustManager.checkClientTrusted(chain, "RSA"))
            .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("skips CRL when chain has no CDP")
    void skipsCrlWhenNoCdp() throws Exception {
        CrlTestFixtures.TestCa caWithoutCdp = CrlTestFixtures.createTestCa(null);
        CrlTestFixtures.ClientCert client = CrlTestFixtures.createClientCert(
            caWithoutCdp, BigInteger.valueOf(44), null);
        X509Certificate[] chain = new X509Certificate[] {
            client.certificate(), caWithoutCdp.certificate()
        };

        assertThatCode(() -> trustManager.checkClientTrusted(chain, "RSA"))
            .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("delegates PKI validation before CRL check")
    void delegatesPkiValidationFirst() throws Exception {
        CrlRevocationChecker checker = org.mockito.Mockito.mock(CrlRevocationChecker.class);
        CrlCheckingTrustManager strictManager =
            new CrlCheckingTrustManager(new RejectingTrustManager(), checker);

        CrlTestFixtures.ClientCert client = CrlTestFixtures.createClientCert(
            ca, BigInteger.valueOf(45), "http://crl.example.test/revocation.crl");
        X509Certificate[] chain = new X509Certificate[] { client.certificate(), ca.certificate() };

        assertThatThrownBy(() -> strictManager.checkClientTrusted(chain, "RSA"))
            .isInstanceOf(CertificateException.class)
            .hasMessageContaining("PKI rejected");

        verify(checker, org.mockito.Mockito.never()).check(any(), any());
    }

    @Test
    @DisplayName("does not run CRL for server certificates")
    void doesNotRunCrlForServerCertificates() throws Exception {
        CrlRevocationChecker checker = org.mockito.Mockito.mock(CrlRevocationChecker.class);
        CrlCheckingTrustManager manager =
            new CrlCheckingTrustManager(new PermissiveTrustManager(), checker);

        assertThatCode(() -> manager.checkServerTrusted(new X509Certificate[] { ca.certificate() }, "RSA"))
            .doesNotThrowAnyException();

        verify(checker, org.mockito.Mockito.never()).check(any(), any());
    }

    private static final class PermissiveTrustManager implements javax.net.ssl.X509TrustManager {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) {
            // no-op
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {
            // no-op
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }

    private static final class RejectingTrustManager implements javax.net.ssl.X509TrustManager {
        @Override
        public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
            throw new CertificateException("PKI rejected");
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain, String authType) {
            // no-op
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }
}
