package com.aliyun.ati.sdk.agent.verification.crl;

import com.aliyun.ati.sdk.agent.VerificationPolicy;
import com.aliyun.ati.sdk.agent.server.ClientRequestVerificationResult;
import com.aliyun.ati.sdk.agent.server.DefaultClientRequestVerifier;
import com.aliyun.ati.sdk.agent.verification.DaneTlsaVerifier;
import com.aliyun.ati.sdk.transparency.verification.BadgeVerificationService;
import com.aliyun.ati.sdk.transparency.verification.ClientVerificationResult;
import com.aliyun.ati.sdk.transparency.verification.VerificationStatus;
import com.github.tomakehurst.wiremock.WireMockServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Set;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.configureFor;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.wireMockConfig;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Dual-track regression: Certificate Revocation (CRL, TLS layer) and Registration Revocation
 * (Badge {@code REVOKED}/{@code EXPIRED}, Client Verification layer) are complementary and
 * independent — either failure rejects the connection.
 *
 * <p>Track A (TLS/CRL) integration coverage lives in
 * {@code com.aliyun.ati.sdk.spring.AtiIdcaCrlMtlsIntegrationTest}.</p>
 */
@DisplayName("Dual-track revocation regression")
class DualTrackRevocationTest {

    private static final BigInteger REVOKED_SERIAL = BigInteger.valueOf(8101);
    private static final BigInteger VALID_SERIAL = BigInteger.valueOf(8102);
    private static final String ATI_URI_SAN = "ati://v1.dual-track.example.com";

    private static final WireMockServer WIRE_MOCK = new WireMockServer(wireMockConfig().dynamicPort());

    private static CrlTestFixtures.TestCa issuingCa;
    private static CrlTestFixtures.ClientCert revokedClient;
    private static CrlTestFixtures.ClientCert validClient;
    private static CrlRevocationChecker crlChecker;
    private static X509Certificate[] validChain;
    private static X509Certificate[] revokedChain;

    @BeforeAll
    static void setUpFixtures() throws Exception {
        WIRE_MOCK.start();
        configureFor("localhost", WIRE_MOCK.port());

        String crlUrl = "http://localhost:" + WIRE_MOCK.port() + "/crl";
        issuingCa = CrlTestFixtures.createTestCa(crlUrl);
        revokedClient = CrlTestFixtures.createClientCert(
            issuingCa, REVOKED_SERIAL, crlUrl, ATI_URI_SAN);
        validClient = CrlTestFixtures.createClientCert(
            issuingCa, VALID_SERIAL, crlUrl, ATI_URI_SAN);

        validChain = new X509Certificate[] { validClient.certificate(), issuingCa.certificate() };
        revokedChain = new X509Certificate[] { revokedClient.certificate(), issuingCa.certificate() };

        WIRE_MOCK.stubFor(get(urlEqualTo("/crl"))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/pkix-crl")
                .withBody(CrlTestFixtures.createCrlBytes(
                    issuingCa,
                    Instant.now().plus(1, ChronoUnit.DAYS),
                    Set.of(REVOKED_SERIAL)))));

        crlChecker = new CrlRevocationChecker(new CrlFetcher(new DefaultCrlHttpClient()));
    }

    @AfterAll
    static void tearDownFixtures() {
        WIRE_MOCK.stop();
    }

    @Nested
    @DisplayName("Track A — Certificate Revocation (CRL)")
    class CertificateRevocationTrack {

        @Test
        @DisplayName("rejects revoked serial at CRL layer without Badge involvement")
        void rejectsRevokedSerialAtCrlLayer() {
            CrlRevocationResult result = crlChecker.check(revokedClient.certificate(), revokedChain);

            assertThat(result.isRevoked()).isTrue();
            assertThat(result.shouldRejectConnection()).isTrue();
        }

        @Test
        @DisplayName("passes non-revoked serial at CRL layer")
        void passesNonRevokedSerialAtCrlLayer() {
            CrlRevocationResult result = crlChecker.check(validClient.certificate(), validChain);

            assertThat(result.isPassed()).isTrue();
            assertThat(result.shouldRejectConnection()).isFalse();
        }
    }

    @Nested
    @DisplayName("Track B — Registration Revocation (Badge)")
    class RegistrationRevocationTrack {

        @ParameterizedTest
        @EnumSource(value = VerificationPolicy.class, names = { "ENHANCED", "ADVANCED" })
        @DisplayName("CRL passes but Registration Status invalid → Client Verification rejects")
        void rejectsWhenCrlPassesButRegistrationInvalid(VerificationPolicy policy) throws Exception {
            assertThat(crlChecker.check(validClient.certificate(), validChain).isPassed()).isTrue();

            BadgeVerificationService badgeService = mock(BadgeVerificationService.class);
            when(badgeService.verifyClient(validClient.certificate()))
                .thenReturn(ClientVerificationResult.builder()
                    .status(VerificationStatus.REGISTRATION_INVALID)
                    .warningMessage("Registration status: REVOKED")
                    .build());

            DaneTlsaVerifier daneVerifier = mock(DaneTlsaVerifier.class);
            DefaultClientRequestVerifier verifier = DefaultClientRequestVerifier.builder()
                .badgeVerificationService(badgeService)
                .daneTlsaVerifier(daneVerifier)
                .build();

            ClientRequestVerificationResult result = verifier.verify(validClient.certificate(), policy);

            assertThat(result.verified()).isFalse();
            assertThat(result.errors()).anyMatch(e -> e.contains("REGISTRATION_INVALID"));
            assertThat(result.errors()).anyMatch(e -> e.contains("REVOKED"));
            verify(daneVerifier, never()).getTlsaExpectations(anyString());
        }

        @Test
        @DisplayName("CRL passes but Registration Status EXPIRED → Client Verification rejects")
        void rejectsWhenCrlPassesButRegistrationExpired() {
            assertThat(crlChecker.check(validClient.certificate(), validChain).isPassed()).isTrue();

            BadgeVerificationService badgeService = mock(BadgeVerificationService.class);
            when(badgeService.verifyClient(validClient.certificate()))
                .thenReturn(ClientVerificationResult.builder()
                    .status(VerificationStatus.REGISTRATION_INVALID)
                    .warningMessage("Registration status: EXPIRED")
                    .build());

            DefaultClientRequestVerifier verifier = DefaultClientRequestVerifier.builder()
                .badgeVerificationService(badgeService)
                .daneTlsaVerifier(mock(DaneTlsaVerifier.class))
                .build();

            ClientRequestVerificationResult result =
                verifier.verify(validClient.certificate(), VerificationPolicy.ENHANCED);

            assertThat(result.verified()).isFalse();
            assertThat(result.errors()).anyMatch(e -> e.contains("EXPIRED"));
        }
    }

    @Nested
    @DisplayName("Complementary tracks")
    class ComplementaryTracks {

        @Test
        @DisplayName("CRL revoked serial is rejected regardless of hypothetical Badge pass")
        void crlRejectionIsIndependentOfBadge() {
            BadgeVerificationService badgeService = mock(BadgeVerificationService.class);
            when(badgeService.verifyClient(revokedClient.certificate()))
                .thenReturn(ClientVerificationResult.builder()
                    .status(VerificationStatus.VERIFIED)
                    .build());

            CrlRevocationResult crlResult = crlChecker.check(revokedClient.certificate(), revokedChain);

            assertThat(crlResult.shouldRejectConnection()).isTrue();
            verify(badgeService, never()).verifyClient(any());
        }

        @Test
        @DisplayName("BASIC policy skips Badge even when CRL would pass")
        void basicPolicySkipsBadgeTrack() {
            assertThat(crlChecker.check(validClient.certificate(), validChain).isPassed()).isTrue();

            BadgeVerificationService badgeService = mock(BadgeVerificationService.class);
            DefaultClientRequestVerifier verifier = DefaultClientRequestVerifier.builder()
                .badgeVerificationService(badgeService)
                .build();

            ClientRequestVerificationResult result =
                verifier.verify(validClient.certificate(), VerificationPolicy.BASIC);

            assertThat(result.verified()).isTrue();
            verify(badgeService, never()).verifyClient(any());
        }
    }
}
