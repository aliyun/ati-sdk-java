package com.aliyun.ati.sdk.agent.verification;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;
import org.xbill.DNS.Flags;
import org.xbill.DNS.Header;
import org.xbill.DNS.Message;
import org.xbill.DNS.Record;
import org.xbill.DNS.Section;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.TLSARecord;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class DefaultDaneTlsaVerifierFactoryTest {

    private static final String TEST_HOSTNAME = "agent.example.com";
    private static final int TEST_PORT = 443;

    @Nested
    @DisplayName("Injectable factories")
    class InjectableFactoryTests {

        @Test
        @DisplayName("Constructor should accept custom resolver factory")
        void constructorShouldAcceptCustomResolverFactory() throws Exception {
            // Given
            DaneConfig config = DaneConfig.builder()
                .policy(DanePolicy.VALIDATE_IF_PRESENT)
                .resolver(DnsResolverConfig.CLOUDFLARE)
                .validationMode(DnssecValidationMode.TRUST_RESOLVER)
                .cacheTtl(Duration.ZERO)
                .build();

            ResolverFactory mockFactory = mock(ResolverFactory.class);
            SimpleResolver mockResolver = mock(SimpleResolver.class);
            CertificateFetcher mockFetcher = mock(CertificateFetcher.class);

            when(mockFactory.create(anyString())).thenReturn(mockResolver);

            byte[] certData = hexToBytes("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2");
            Message mockResponse = createMockDnsResponse(true, certData);
            when(mockResolver.send(any(Message.class))).thenReturn(mockResponse);

            // When
            DefaultDaneTlsaVerifier verifier = new DefaultDaneTlsaVerifier(config, mockFactory, mockFetcher);
            List<DaneTlsaVerifier.TlsaExpectation> expectations =
                    verifier.getTlsaExpectations(TEST_HOSTNAME, TEST_PORT);

            // Then
            assertThat(expectations).hasSize(1);
            verify(mockFactory).create(anyString());
        }

        @Test
        @DisplayName("Constructor should accept custom certificate fetcher")
        void constructorShouldAcceptCustomCertificateFetcher() throws Exception {
            // Given
            DaneConfig config = DaneConfig.builder()
                .policy(DanePolicy.VALIDATE_IF_PRESENT)
                .resolver(DnsResolverConfig.CLOUDFLARE)
                .validationMode(DnssecValidationMode.TRUST_RESOLVER)
                .cacheTtl(Duration.ZERO)
                .build();

            ResolverFactory mockFactory = mock(ResolverFactory.class);
            SimpleResolver mockResolver = mock(SimpleResolver.class);
            CertificateFetcher mockFetcher = mock(CertificateFetcher.class);
            X509Certificate mockCert = mock(X509Certificate.class);

            when(mockFactory.create(anyString())).thenReturn(mockResolver);
            when(mockFetcher.getCertificate(anyString(), anyInt())).thenReturn(mockCert);

            byte[] certData = hexToBytes("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2");
            Message mockResponse = createMockDnsResponse(true, certData);
            when(mockResolver.send(any(Message.class))).thenReturn(mockResponse);

            // When
            DefaultDaneTlsaVerifier verifier = new DefaultDaneTlsaVerifier(config, mockFactory, mockFetcher);

            // Then - verifier created successfully with injected dependencies
            assertThat(verifier).isNotNull();
        }

        @Test
        @DisplayName("verifyTlsa should use injected certificate fetcher")
        void verifyTlsaShouldUseInjectedCertificateFetcher() throws Exception {
            // Given
            DaneConfig config = DaneConfig.builder()
                .policy(DanePolicy.REQUIRED)
                .resolver(DnsResolverConfig.CLOUDFLARE)
                .validationMode(DnssecValidationMode.TRUST_RESOLVER)
                .cacheTtl(Duration.ZERO)
                .build();

            ResolverFactory mockFactory = mock(ResolverFactory.class);
            SimpleResolver mockResolver = mock(SimpleResolver.class);
            CertificateFetcher mockFetcher = mock(CertificateFetcher.class);
            X509Certificate mockCert = mock(X509Certificate.class);

            when(mockFactory.create(anyString())).thenReturn(mockResolver);
            when(mockFetcher.getCertificate(TEST_HOSTNAME, TEST_PORT)).thenReturn(mockCert);

            // Mock certificate with encoded form for hash comparison
            byte[] certData = hexToBytes("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2");
            when(mockCert.getEncoded()).thenReturn(certData);

            Message mockResponse = createMockDnsResponse(true, certData);
            when(mockResolver.send(any(Message.class))).thenReturn(mockResponse);

            DefaultDaneTlsaVerifier verifier = new DefaultDaneTlsaVerifier(config, mockFactory, mockFetcher);

            // When
            DaneTlsaVerifier.TlsaResult result = verifier.verifyTlsa(TEST_HOSTNAME, TEST_PORT);

            // Then
            assertThat(result).isNotNull();
            verify(mockFetcher).getCertificate(TEST_HOSTNAME, TEST_PORT);
        }

        @Test
        @DisplayName("verifyTlsa should handle certificate fetch failure")
        void verifyTlsaShouldHandleCertificateFetchFailure() throws Exception {
            // Given
            DaneConfig config = DaneConfig.builder()
                .policy(DanePolicy.REQUIRED)
                .resolver(DnsResolverConfig.CLOUDFLARE)
                .validationMode(DnssecValidationMode.TRUST_RESOLVER)
                .cacheTtl(Duration.ZERO)
                .build();

            ResolverFactory mockFactory = mock(ResolverFactory.class);
            SimpleResolver mockResolver = mock(SimpleResolver.class);
            CertificateFetcher mockFetcher = mock(CertificateFetcher.class);

            when(mockFactory.create(anyString())).thenReturn(mockResolver);
            when(mockFetcher.getCertificate(anyString(), anyInt()))
                .thenThrow(new IOException("Connection refused"));

            byte[] certData = hexToBytes("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2");
            Message mockResponse = createMockDnsResponse(true, certData);
            when(mockResolver.send(any(Message.class))).thenReturn(mockResponse);

            DefaultDaneTlsaVerifier verifier = new DefaultDaneTlsaVerifier(config, mockFactory, mockFetcher);

            // When
            DaneTlsaVerifier.TlsaResult result = verifier.verifyTlsa(TEST_HOSTNAME, TEST_PORT);

            // Then - should fail gracefully
            assertThat(result.verified()).isFalse();
            assertThat(result.reason()).containsIgnoringCase("certificate");
        }

        @Test
        @DisplayName("Should use system resolver when configured with null dns server")
        void shouldUseSystemResolverWhenConfiguredWithNull() throws Exception {
            // Given
            DaneConfig config = DaneConfig.builder()
                .policy(DanePolicy.VALIDATE_IF_PRESENT)
                .resolver(DnsResolverConfig.SYSTEM)
                .validationMode(DnssecValidationMode.TRUST_RESOLVER)
                .cacheTtl(Duration.ZERO)
                .build();

            ResolverFactory mockFactory = mock(ResolverFactory.class);
            SimpleResolver mockResolver = mock(SimpleResolver.class);
            CertificateFetcher mockFetcher = mock(CertificateFetcher.class);

            // System resolver means null dns server, but TRUST_RESOLVER falls back to default
            when(mockFactory.create(anyString())).thenReturn(mockResolver);

            Message mockResponse = createMockDnsResponseWithEmptyAnswer(true);
            when(mockResolver.send(any(Message.class))).thenReturn(mockResponse);

            DefaultDaneTlsaVerifier verifier = new DefaultDaneTlsaVerifier(config, mockFactory, mockFetcher);

            // When
            boolean hasTlsa = verifier.hasTlsaRecord(TEST_HOSTNAME, TEST_PORT);

            // Then
            assertThat(hasTlsa).isFalse();
        }
    }

    // ==================== TlsaExpectation Tests ====================

    @Nested
    @DisplayName("TlsaExpectation")
    class TlsaExpectationTests {

        @Test
        @DisplayName("expectedData should be defensively copied on construction")
        void expectedDataShouldBeDefensivelyCopiedOnConstruction() {
            byte[] originalData = hexToBytes("a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4");
            DaneTlsaVerifier.TlsaExpectation expectation = new DaneTlsaVerifier.TlsaExpectation(1, 1, originalData);

            // Modify original data
            originalData[0] = (byte) 0xFF;

            // Expectation should have original value
            assertThat(expectation.expectedData()[0]).isNotEqualTo((byte) 0xFF);
        }

        @Test
        @DisplayName("expectedData accessor should return defensive copy")
        void expectedDataAccessorShouldReturnDefensiveCopy() {
            byte[] certData = hexToBytes("a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4");
            DaneTlsaVerifier.TlsaExpectation expectation = new DaneTlsaVerifier.TlsaExpectation(1, 1, certData);

            // Get data and modify
            byte[] retrieved = expectation.expectedData();
            retrieved[0] = (byte) 0xFF;

            // Second retrieval should have original value
            assertThat(expectation.expectedData()[0]).isNotEqualTo((byte) 0xFF);
        }

        @Test
        @DisplayName("expectedData with null should work")
        void expectedDataWithNullShouldWork() {
            DaneTlsaVerifier.TlsaExpectation expectation = new DaneTlsaVerifier.TlsaExpectation(1, 1, null);

            assertThat(expectation.expectedData()).isNull();
        }

        @Test
        @DisplayName("selector and matchingType should be accessible")
        void selectorAndMatchingTypeShouldBeAccessible() {
            byte[] certData = hexToBytes("a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4");
            DaneTlsaVerifier.TlsaExpectation expectation = new DaneTlsaVerifier.TlsaExpectation(0, 2, certData);

            assertThat(expectation.selector()).isEqualTo(0);
            assertThat(expectation.matchingType()).isEqualTo(2);
        }
    }


    private Message createMockDnsResponse(boolean adFlag, byte[] certData) throws Exception {
        Message mockResponse = mock(Message.class);
        Header mockHeader = mock(Header.class);

        when(mockResponse.getHeader()).thenReturn(mockHeader);
        when(mockHeader.getFlag(Flags.AD)).thenReturn(adFlag);

        TLSARecord mockRecord = createMockTlsaRecord(3, 1, 1, certData);
        when(mockResponse.getSectionArray(Section.ANSWER)).thenReturn(new Record[]{mockRecord});

        return mockResponse;
    }

    private Message createMockDnsResponseWithMultipleRecords(boolean adFlag, byte[] certData1, byte[] certData2)
            throws Exception {
        Message mockResponse = mock(Message.class);
        Header mockHeader = mock(Header.class);

        when(mockResponse.getHeader()).thenReturn(mockHeader);
        when(mockHeader.getFlag(Flags.AD)).thenReturn(adFlag);

        TLSARecord mockRecord1 = createMockTlsaRecord(3, 1, 1, certData1);
        TLSARecord mockRecord2 = createMockTlsaRecord(3, 1, 1, certData2);
        when(mockResponse.getSectionArray(Section.ANSWER)).thenReturn(new Record[]{mockRecord1, mockRecord2});

        return mockResponse;
    }

    private Message createMockDnsResponseWithEmptyAnswer(boolean adFlag) {
        Message mockResponse = mock(Message.class);
        Header mockHeader = mock(Header.class);

        when(mockResponse.getHeader()).thenReturn(mockHeader);
        when(mockHeader.getFlag(Flags.AD)).thenReturn(adFlag);
        when(mockResponse.getSectionArray(Section.ANSWER)).thenReturn(new Record[]{});

        return mockResponse;
    }

    private TLSARecord createMockTlsaRecord(int usage, int selector, int matchingType, byte[] certData) {
        TLSARecord mockRecord = mock(TLSARecord.class);
        when(mockRecord.getCertificateUsage()).thenReturn(usage);
        when(mockRecord.getSelector()).thenReturn(selector);
        when(mockRecord.getMatchingType()).thenReturn(matchingType);
        when(mockRecord.getCertificateAssociationData()).thenReturn(certData);
        return mockRecord;
    }

    private byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
}
