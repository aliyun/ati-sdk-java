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

import java.io.IOException;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockConstruction;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
class DefaultDaneTlsaVerifierVerifyTest {

    private static final String TEST_HOSTNAME = "agent.example.com";
    private static final int TEST_PORT = 443;

    // ==================== verifyTlsa Tests ====================

    @Nested
    @DisplayName("verifyTlsa")
    class VerifyTlsaTests {

        @Test
        @DisplayName("Should return skipped when policy is DISABLED")
        void shouldReturnSkippedWhenDisabled() {
            // Given
            DaneConfig config = DaneConfig.builder()
                .policy(DanePolicy.DISABLED)
                .build();

            DefaultDaneTlsaVerifier verifier = new DefaultDaneTlsaVerifier(config);

            // When
            DaneTlsaVerifier.TlsaResult result = verifier.verifyTlsa(TEST_HOSTNAME, TEST_PORT);

            // Then
            assertThat(result.isSkipped()).isTrue();
            assertThat(result.reason()).contains("disabled");
        }

        @Test
        @DisplayName("Should return failure when TLSA required but not found")
        void shouldReturnFailureWhenRequiredButNotFound() throws Exception {
            // Given
            DaneConfig config = DaneConfig.builder()
                .policy(DanePolicy.REQUIRED)
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
                DaneTlsaVerifier.TlsaResult result = verifier.verifyTlsa(TEST_HOSTNAME, TEST_PORT);

                // Then
                assertThat(result.verified()).isFalse();
                assertThat(result.reason()).contains("required but not found");
            }
        }

        @Test
        @DisplayName("Should return noRecord when VALIDATE_IF_PRESENT and no record")
        void shouldReturnNoRecordWhenValidateIfPresentAndNoRecord() throws Exception {
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
                DaneTlsaVerifier.TlsaResult result = verifier.verifyTlsa(TEST_HOSTNAME, TEST_PORT);

                // Then
                assertThat(result.verified()).isFalse();
                assertThat(result.reason()).contains("No TLSA record");
            }
        }

        @Test
        @DisplayName("Should return failure when DNSSEC validation fails")
        void shouldReturnFailureWhenDnssecFails() throws Exception {
            // Given
            DaneConfig config = DaneConfig.builder()
                .policy(DanePolicy.VALIDATE_IF_PRESENT)
                .resolver(DnsResolverConfig.CLOUDFLARE)
                .validationMode(DnssecValidationMode.TRUST_RESOLVER)
                .cacheTtl(Duration.ZERO)
                .build();

            byte[] certData = hexToBytes("a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2");
            // AD flag NOT set - DNSSEC validation failure
            Message mockResponse = createMockDnsResponse(false, certData);

            try (MockedConstruction<SimpleResolver> resolverMock = mockConstruction(SimpleResolver.class,
                    (mock, context) -> {
                        when(mock.send(any(Message.class))).thenReturn(mockResponse);
                    })) {

                DefaultDaneTlsaVerifier verifier = new DefaultDaneTlsaVerifier(config);

                // When
                DaneTlsaVerifier.TlsaResult result = verifier.verifyTlsa(TEST_HOSTNAME, TEST_PORT);

                // Then
                assertThat(result.verified()).isFalse();
                assertThat(result.reason()).contains("DNSSEC");
            }
        }

        @Test
        @DisplayName("Should return failure when DNS query fails")
        void shouldReturnFailureWhenDnsQueryFails() throws Exception {
            // Given
            DaneConfig config = DaneConfig.builder()
                .policy(DanePolicy.VALIDATE_IF_PRESENT)
                .resolver(DnsResolverConfig.CLOUDFLARE)
                .validationMode(DnssecValidationMode.TRUST_RESOLVER)
                .cacheTtl(Duration.ZERO)
                .build();

            try (MockedConstruction<SimpleResolver> resolverMock = mockConstruction(SimpleResolver.class,
                    (mock, context) -> {
                        when(mock.send(any(Message.class))).thenThrow(new IOException("DNS timeout"));
                    })) {

                DefaultDaneTlsaVerifier verifier = new DefaultDaneTlsaVerifier(config);

                // When
                DaneTlsaVerifier.TlsaResult result = verifier.verifyTlsa(TEST_HOSTNAME, TEST_PORT);

                // Then
                assertThat(result.verified()).isFalse();
                assertThat(result.reason()).contains("DNS query failed");
            }
        }
    }

    // ==================== hasTlsaRecord Tests ====================

    @Nested
    @DisplayName("hasTlsaRecord")
    class HasTlsaRecordTests {

        @Test
        @DisplayName("Should return false when policy is DISABLED")
        void shouldReturnFalseWhenDisabled() {
            // Given
            DaneConfig config = DaneConfig.builder()
                .policy(DanePolicy.DISABLED)
                .build();

            DefaultDaneTlsaVerifier verifier = new DefaultDaneTlsaVerifier(config);

            // When
            boolean hasTlsa = verifier.hasTlsaRecord(TEST_HOSTNAME, TEST_PORT);

            // Then
            assertThat(hasTlsa).isFalse();
        }

        @Test
        @DisplayName("Should return true when TLSA record exists")
        void shouldReturnTrueWhenTlsaExists() throws Exception {
            // Given
            DaneConfig config = DaneConfig.builder()
                .policy(DanePolicy.VALIDATE_IF_PRESENT)
                .resolver(DnsResolverConfig.CLOUDFLARE)
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
                boolean hasTlsa = verifier.hasTlsaRecord(TEST_HOSTNAME, TEST_PORT);

                // Then
                assertThat(hasTlsa).isTrue();
            }
        }

        @Test
        @DisplayName("Should return false when exception occurs")
        void shouldReturnFalseWhenExceptionOccurs() throws Exception {
            // Given
            DaneConfig config = DaneConfig.builder()
                .policy(DanePolicy.VALIDATE_IF_PRESENT)
                .resolver(DnsResolverConfig.CLOUDFLARE)
                .validationMode(DnssecValidationMode.TRUST_RESOLVER)
                .cacheTtl(Duration.ZERO)
                .build();

            try (MockedConstruction<SimpleResolver> resolverMock = mockConstruction(SimpleResolver.class,
                    (mock, context) -> {
                        when(mock.send(any(Message.class))).thenThrow(new IOException("DNS error"));
                    })) {

                DefaultDaneTlsaVerifier verifier = new DefaultDaneTlsaVerifier(config);

                // When
                boolean hasTlsa = verifier.hasTlsaRecord(TEST_HOSTNAME, TEST_PORT);

                // Then
                assertThat(hasTlsa).isFalse();
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

    // ==================== TlsaResult Tests ====================

    @Nested
    @DisplayName("TlsaResult")
    class TlsaResultTests {

        @Test
        @DisplayName("success() should create verified result")
        void successShouldCreateVerifiedResult() {
            byte[] certData = hexToBytes("a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4");
            DaneTlsaVerifier.TlsaResult result = DaneTlsaVerifier.TlsaResult.success("SPKI-SHA256", certData);

            assertThat(result.verified()).isTrue();
            assertThat(result.matchType()).isEqualTo("SPKI-SHA256");
            assertThat(result.reason()).isNull();
            assertThat(result.certificateData()).isEqualTo(certData);
            assertThat(result.isSkipped()).isFalse();
        }

        @Test
        @DisplayName("failure() should create non-verified result with reason")
        void failureShouldCreateNonVerifiedResult() {
            DaneTlsaVerifier.TlsaResult result = DaneTlsaVerifier.TlsaResult.failure("Certificate mismatch");

            assertThat(result.verified()).isFalse();
            assertThat(result.matchType()).isNull();
            assertThat(result.reason()).isEqualTo("Certificate mismatch");
            assertThat(result.certificateData()).isNull();
            assertThat(result.isSkipped()).isFalse();
        }

        @Test
        @DisplayName("noRecord() should create result indicating no TLSA record")
        void noRecordShouldCreateCorrectResult() {
            DaneTlsaVerifier.TlsaResult result = DaneTlsaVerifier.TlsaResult.noRecord();

            assertThat(result.verified()).isFalse();
            assertThat(result.matchType()).isNull();
            assertThat(result.reason()).isEqualTo("No TLSA record found");
            assertThat(result.certificateData()).isNull();
            assertThat(result.isSkipped()).isFalse();
        }

        @Test
        @DisplayName("skipped() should create skipped result")
        void skippedShouldCreateSkippedResult() {
            DaneTlsaVerifier.TlsaResult result = DaneTlsaVerifier.TlsaResult.skipped("DANE verification disabled");

            assertThat(result.verified()).isFalse();
            assertThat(result.matchType()).isEqualTo("SKIPPED");
            assertThat(result.reason()).isEqualTo("DANE verification disabled");
            assertThat(result.certificateData()).isNull();
            assertThat(result.isSkipped()).isTrue();
        }

        @Test
        @DisplayName("certificateData should be defensively copied")
        void certificateDataShouldBeDefensivelyCopied() {
            byte[] originalData = hexToBytes("a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4");
            DaneTlsaVerifier.TlsaResult result = DaneTlsaVerifier.TlsaResult.success("SPKI-SHA256", originalData);

            // Modify original data
            originalData[0] = (byte) 0xFF;

            // Result should have original value
            assertThat(result.certificateData()[0]).isNotEqualTo((byte) 0xFF);
        }

        @Test
        @DisplayName("certificateData accessor should return defensive copy")
        void certificateDataAccessorShouldReturnDefensiveCopy() {
            byte[] certData = hexToBytes("a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4");
            DaneTlsaVerifier.TlsaResult result = DaneTlsaVerifier.TlsaResult.success("SPKI-SHA256", certData);

            // Get certificate data and modify it
            byte[] retrieved = result.certificateData();
            retrieved[0] = (byte) 0xFF;

            // Second retrieval should have original value
            assertThat(result.certificateData()[0]).isNotEqualTo((byte) 0xFF);
        }

        @Test
        @DisplayName("success with null certificateData should work")
        void successWithNullCertificateDataShouldWork() {
            DaneTlsaVerifier.TlsaResult result = DaneTlsaVerifier.TlsaResult.success("SPKI-SHA256", null);

            assertThat(result.verified()).isTrue();
            assertThat(result.certificateData()).isNull();
        }

        @Test
        @DisplayName("record constructor should defensively copy")
        void recordConstructorShouldDefensivelyCopy() {
            byte[] certData = hexToBytes("a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4a1b2c3d4");
            DaneTlsaVerifier.TlsaResult result = new DaneTlsaVerifier.TlsaResult(true, "test", null, certData);

            // Modify original
            certData[0] = (byte) 0xFF;

            // Result should be unaffected
            assertThat(result.certificateData()[0]).isNotEqualTo((byte) 0xFF);
        }
    }

}
