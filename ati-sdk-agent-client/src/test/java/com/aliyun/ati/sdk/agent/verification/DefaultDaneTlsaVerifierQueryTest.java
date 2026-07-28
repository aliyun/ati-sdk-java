package com.aliyun.ati.sdk.agent.verification;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.MockedConstruction;
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

import java.time.Duration;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class DefaultDaneTlsaVerifierQueryTest {

    private static final String TEST_HOSTNAME = "agent.example.com";
    private static final int TEST_PORT = 443;

    @Nested
    @DisplayName("queryTlsaRecordsTrustResolver")
    class QueryTlsaRecordsTrustResolverTests {

        @Test
        @DisplayName("Should return TLSA records when AD flag is set")
        void shouldReturnTlsaRecordsWhenAdFlagSet() throws Exception {
            // Given
            DaneConfig config = DaneConfig.builder()
                .policy(DanePolicy.VALIDATE_IF_PRESENT)
                .resolver(DnsResolverConfig.CLOUDFLARE)
                .validationMode(DnssecValidationMode.TRUST_RESOLVER)
                .cacheTtl(Duration.ZERO)
                .build();

            byte[] certData = hexToBytes("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2");

            // Mock DNS response with AD flag
            Message mockResponse = createMockDnsResponse(true, certData);

            try (MockedConstruction<SimpleResolver> resolverMock = mockConstruction(SimpleResolver.class,
                    (mock, context) -> {
                        when(mock.send(any(Message.class))).thenReturn(mockResponse);
                    })) {

                DefaultDaneTlsaVerifier verifier = new DefaultDaneTlsaVerifier(config);

                // When
                List<DaneTlsaVerifier.TlsaExpectation> expectations =
                    verifier.getTlsaExpectations(TEST_HOSTNAME, TEST_PORT);

                // Then
                assertThat(expectations).hasSize(1);
                assertThat(expectations.get(0).selector()).isEqualTo(1);
                assertThat(expectations.get(0).matchingType()).isEqualTo(1);
            }
        }

        @Test
        @DisplayName("Should throw DnssecValidationException when AD flag not set")
        void shouldThrowWhenAdFlagNotSet() throws Exception {
            // Given
            DaneConfig config = DaneConfig.builder()
                .policy(DanePolicy.VALIDATE_IF_PRESENT)
                .resolver(DnsResolverConfig.CLOUDFLARE)
                .validationMode(DnssecValidationMode.TRUST_RESOLVER)
                .cacheTtl(Duration.ZERO)
                .build();

            byte[] certData = hexToBytes("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2");

            // Mock DNS response WITHOUT AD flag
            Message mockResponse = createMockDnsResponse(false, certData);

            try (MockedConstruction<SimpleResolver> resolverMock = mockConstruction(SimpleResolver.class,
                    (mock, context) -> {
                        when(mock.send(any(Message.class))).thenReturn(mockResponse);
                    })) {

                DefaultDaneTlsaVerifier verifier = new DefaultDaneTlsaVerifier(config);

                // When - hasTlsaRecord should return false due to DNSSEC failure
                boolean hasTlsa = verifier.hasTlsaRecord(TEST_HOSTNAME, TEST_PORT);

                // Then
                assertThat(hasTlsa).isFalse();
            }
        }

        @Test
        @DisplayName("Should return empty list when response is null")
        void shouldReturnEmptyWhenResponseNull() throws Exception {
            // Given
            DaneConfig config = DaneConfig.builder()
                .policy(DanePolicy.VALIDATE_IF_PRESENT)
                .resolver(DnsResolverConfig.CLOUDFLARE)
                .validationMode(DnssecValidationMode.TRUST_RESOLVER)
                .cacheTtl(Duration.ZERO)
                .build();

            try (MockedConstruction<SimpleResolver> resolverMock = mockConstruction(SimpleResolver.class,
                    (mock, context) -> {
                        when(mock.send(any(Message.class))).thenReturn(null);
                    })) {

                DefaultDaneTlsaVerifier verifier = new DefaultDaneTlsaVerifier(config);

                // When
                boolean hasTlsa = verifier.hasTlsaRecord(TEST_HOSTNAME, TEST_PORT);

                // Then - should return false (no records)
                assertThat(hasTlsa).isFalse();
            }
        }

        @Test
        @DisplayName("Should return empty list when header is null")
        void shouldReturnEmptyWhenHeaderNull() throws Exception {
            // Given
            DaneConfig config = DaneConfig.builder()
                .policy(DanePolicy.VALIDATE_IF_PRESENT)
                .resolver(DnsResolverConfig.CLOUDFLARE)
                .validationMode(DnssecValidationMode.TRUST_RESOLVER)
                .cacheTtl(Duration.ZERO)
                .build();

            Message mockResponse = mock(Message.class);
            when(mockResponse.getHeader()).thenReturn(null);

            try (MockedConstruction<SimpleResolver> resolverMock = mockConstruction(SimpleResolver.class,
                    (mock, context) -> {
                        when(mock.send(any(Message.class))).thenReturn(mockResponse);
                    })) {

                DefaultDaneTlsaVerifier verifier = new DefaultDaneTlsaVerifier(config);

                // When
                boolean hasTlsa = verifier.hasTlsaRecord(TEST_HOSTNAME, TEST_PORT);

                // Then
                assertThat(hasTlsa).isFalse();
            }
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
