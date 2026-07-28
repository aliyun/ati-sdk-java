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

/**
 * Unit tests for {@link DefaultDaneTlsaVerifier} that mock external dependencies
 * (DNS resolver) to test the actual code paths.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class DefaultDaneTlsaVerifierTest {

    private static final String TEST_HOSTNAME = "agent.example.com";
    private static final int TEST_PORT = 443;

    // ==================== queryTlsaRecordsTrustResolver Tests ====================

    // ==================== extractAllTlsaFromResponse Tests ====================

    @Nested
    @DisplayName("extractAllTlsaFromResponse")
    class ExtractAllTlsaFromResponseTests {

        @Test
        @DisplayName("Should extract multiple TLSA records")
        void shouldExtractMultipleTlsaRecords() throws Exception {
            // Given
            DaneConfig config = DaneConfig.builder()
                .policy(DanePolicy.VALIDATE_IF_PRESENT)
                .resolver(DnsResolverConfig.CLOUDFLARE)
                .validationMode(DnssecValidationMode.TRUST_RESOLVER)
                .cacheTtl(Duration.ZERO)
                .build();

            byte[] certData1 = hexToBytes("1111111111111111111111111111111111111111111111111111111111111111");
            byte[] certData2 = hexToBytes("2222222222222222222222222222222222222222222222222222222222222222");

            Message mockResponse = createMockDnsResponseWithMultipleRecords(true, certData1, certData2);

            try (MockedConstruction<SimpleResolver> resolverMock = mockConstruction(SimpleResolver.class,
                    (mock, context) -> {
                        when(mock.send(any(Message.class))).thenReturn(mockResponse);
                    })) {

                DefaultDaneTlsaVerifier verifier = new DefaultDaneTlsaVerifier(config);

                // When
                List<DaneTlsaVerifier.TlsaExpectation> expectations =
                    verifier.getTlsaExpectations(TEST_HOSTNAME, TEST_PORT);

                // Then
                assertThat(expectations).hasSize(2);
            }
        }

        @Test
        @DisplayName("Should return empty when no TLSA records in answer")
        void shouldReturnEmptyWhenNoTlsaRecords() throws Exception {
            // Given
            DaneConfig config = DaneConfig.builder()
                .policy(DanePolicy.VALIDATE_IF_PRESENT)
                .resolver(DnsResolverConfig.CLOUDFLARE)
                .validationMode(DnssecValidationMode.TRUST_RESOLVER)
                .cacheTtl(Duration.ZERO)
                .build();

            Message mockResponse = createMockDnsResponseWithEmptyAnswer(true);

            try (MockedConstruction<SimpleResolver> resolverMock = mockConstruction(SimpleResolver.class,
                    (mock, context) -> {
                        when(mock.send(any(Message.class))).thenReturn(mockResponse);
                    })) {

                DefaultDaneTlsaVerifier verifier = new DefaultDaneTlsaVerifier(config);

                // When
                List<DaneTlsaVerifier.TlsaExpectation> expectations =
                    verifier.getTlsaExpectations(TEST_HOSTNAME, TEST_PORT);

                // Then
                assertThat(expectations).isEmpty();
            }
        }

        @Test
        @DisplayName("Should return empty when answer array is null")
        void shouldReturnEmptyWhenAnswerArrayNull() throws Exception {
            // Given
            DaneConfig config = DaneConfig.builder()
                .policy(DanePolicy.VALIDATE_IF_PRESENT)
                .resolver(DnsResolverConfig.CLOUDFLARE)
                .validationMode(DnssecValidationMode.TRUST_RESOLVER)
                .cacheTtl(Duration.ZERO)
                .build();

            Message mockResponse = mock(Message.class);
            Header mockHeader = mock(Header.class);
            when(mockResponse.getHeader()).thenReturn(mockHeader);
            when(mockHeader.getFlag(Flags.AD)).thenReturn(true);
            when(mockResponse.getSectionArray(Section.ANSWER)).thenReturn(null);

            try (MockedConstruction<SimpleResolver> resolverMock = mockConstruction(SimpleResolver.class,
                    (mock, context) -> {
                        when(mock.send(any(Message.class))).thenReturn(mockResponse);
                    })) {

                DefaultDaneTlsaVerifier verifier = new DefaultDaneTlsaVerifier(config);

                // When
                List<DaneTlsaVerifier.TlsaExpectation> expectations =
                    verifier.getTlsaExpectations(TEST_HOSTNAME, TEST_PORT);

                // Then
                assertThat(expectations).isEmpty();
            }
        }

        @Test
        @DisplayName("Should handle mixed record types in answer")
        void shouldHandleMixedRecordTypesInAnswer() throws Exception {
            // Given
            DaneConfig config = DaneConfig.builder()
                .policy(DanePolicy.VALIDATE_IF_PRESENT)
                .resolver(DnsResolverConfig.CLOUDFLARE)
                .validationMode(DnssecValidationMode.TRUST_RESOLVER)
                .cacheTtl(Duration.ZERO)
                .build();

            byte[] certData = hexToBytes("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2");

            Message mockResponse = mock(Message.class);
            Header mockHeader = mock(Header.class);
            when(mockResponse.getHeader()).thenReturn(mockHeader);
            when(mockHeader.getFlag(Flags.AD)).thenReturn(true);

            // Mix of TLSA and non-TLSA records
            TLSARecord tlsaRecord = createMockTlsaRecord(3, 1, 1, certData);
            Record otherRecord = mock(Record.class); // Not a TLSA record
            when(mockResponse.getSectionArray(Section.ANSWER)).thenReturn(new Record[]{otherRecord, tlsaRecord});

            try (MockedConstruction<SimpleResolver> resolverMock = mockConstruction(SimpleResolver.class,
                    (mock, context) -> {
                        when(mock.send(any(Message.class))).thenReturn(mockResponse);
                    })) {

                DefaultDaneTlsaVerifier verifier = new DefaultDaneTlsaVerifier(config);

                // When
                List<DaneTlsaVerifier.TlsaExpectation> expectations =
                    verifier.getTlsaExpectations(TEST_HOSTNAME, TEST_PORT);

                // Then - should only include the TLSA record
                assertThat(expectations).hasSize(1);
            }
        }
    }

    // ==================== createSimpleResolver Tests ====================

    @Nested
    @DisplayName("createSimpleResolver")
    class CreateSimpleResolverTests {

        @Test
        @DisplayName("Should use configured DNS server - Google")
        void shouldUseConfiguredDnsServerGoogle() throws Exception {
            // Given
            DaneConfig config = DaneConfig.builder()
                .policy(DanePolicy.VALIDATE_IF_PRESENT)
                .resolver(DnsResolverConfig.GOOGLE) // 8.8.8.8
                .validationMode(DnssecValidationMode.TRUST_RESOLVER)
                .cacheTtl(Duration.ZERO)
                .build();

            byte[] certData = hexToBytes("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2");
            Message mockResponse = createMockDnsResponse(true, certData);

            try (MockedConstruction<SimpleResolver> resolverMock = mockConstruction(SimpleResolver.class,
                    (mock, context) -> {
                        when(mock.send(any(Message.class))).thenReturn(mockResponse);
                    })) {

                DefaultDaneTlsaVerifier verifier = new DefaultDaneTlsaVerifier(config);

                // When
                verifier.getTlsaExpectations(TEST_HOSTNAME, TEST_PORT);

                // Then - verify resolver was constructed
                assertThat(resolverMock.constructed()).hasSize(1);
            }
        }

        @Test
        @DisplayName("Should use configured DNS server - Quad9")
        void shouldUseConfiguredDnsServerQuad9() throws Exception {
            // Given
            DaneConfig config = DaneConfig.builder()
                .policy(DanePolicy.VALIDATE_IF_PRESENT)
                .resolver(DnsResolverConfig.QUAD9) // 9.9.9.9
                .validationMode(DnssecValidationMode.TRUST_RESOLVER)
                .cacheTtl(Duration.ZERO)
                .build();

            byte[] certData = hexToBytes("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2");
            Message mockResponse = createMockDnsResponse(true, certData);

            try (MockedConstruction<SimpleResolver> resolverMock = mockConstruction(SimpleResolver.class,
                    (mock, context) -> {
                        when(mock.send(any(Message.class))).thenReturn(mockResponse);
                    })) {

                DefaultDaneTlsaVerifier verifier = new DefaultDaneTlsaVerifier(config);

                // When
                verifier.getTlsaExpectations(TEST_HOSTNAME, TEST_PORT);

                // Then - verify resolver was constructed
                assertThat(resolverMock.constructed()).hasSize(1);
            }
        }

        @Test
        @DisplayName("Should use default resolver when SYSTEM with TRUST_RESOLVER mode")
        void shouldUseDefaultResolverForTrustResolverMode() throws Exception {
            // Given - SYSTEM resolver with TRUST_RESOLVER mode should fallback to default
            DaneConfig config = DaneConfig.builder()
                .policy(DanePolicy.VALIDATE_IF_PRESENT)
                .resolver(DnsResolverConfig.SYSTEM)
                .validationMode(DnssecValidationMode.TRUST_RESOLVER)
                .cacheTtl(Duration.ZERO)
                .build();

            byte[] certData = hexToBytes("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2");
            Message mockResponse = createMockDnsResponse(true, certData);

            try (MockedConstruction<SimpleResolver> resolverMock = mockConstruction(SimpleResolver.class,
                    (mock, context) -> {
                        when(mock.send(any(Message.class))).thenReturn(mockResponse);
                    })) {

                DefaultDaneTlsaVerifier verifier = new DefaultDaneTlsaVerifier(config);

                // When
                verifier.getTlsaExpectations(TEST_HOSTNAME, TEST_PORT);

                // Then - resolver should be created (with default DNSSEC resolver)
                assertThat(resolverMock.constructed()).hasSize(1);
            }
        }
    }

    // ==================== Helper Methods ====================

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
