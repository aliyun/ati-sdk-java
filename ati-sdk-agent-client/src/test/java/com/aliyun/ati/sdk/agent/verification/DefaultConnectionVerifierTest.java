package com.aliyun.ati.sdk.agent.verification;

import com.aliyun.ati.sdk.agent.VerificationPolicy;
import com.aliyun.ati.sdk.transparency.TransparencyClient;
import com.aliyun.ati.sdk.transparency.scitt.ScittExpectation;
import com.aliyun.ati.sdk.transparency.scitt.ScittPreVerifyResult;
import com.aliyun.ati.sdk.transparency.scitt.ScittReceipt;
import com.aliyun.ati.sdk.transparency.scitt.StatusToken;
import com.aliyun.ati.sdk.transparency.verification.ServerVerificationResult;
import com.aliyun.ati.sdk.transparency.verification.ServerVerifier;
import com.aliyun.ati.sdk.transparency.verification.VerificationStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for DefaultConnectionVerifier.
 */
class DefaultConnectionVerifierTest {

    private DaneVerifier mockDaneVerifier;
    private BadgeVerifier mockBadgeVerifier;
    private ScittVerifierAdapter mockScittVerifier;
    private X509Certificate mockCert;

    @BeforeEach
    void setUp() {
        mockDaneVerifier = mock(DaneVerifier.class);
        mockBadgeVerifier = mock(BadgeVerifier.class);
        mockScittVerifier = mock(ScittVerifierAdapter.class);
        mockCert = mock(X509Certificate.class);
    }

    @Test
    void builderCreatesVerifier() {
        DefaultConnectionVerifier verifier = DefaultConnectionVerifier.builder()
            .daneVerifier(mockDaneVerifier)
            .badgeVerifier(mockBadgeVerifier)
            .build();

        assertNotNull(verifier);
    }

    @Test
    void builderWithoutVerifiers() {
        DefaultConnectionVerifier verifier = DefaultConnectionVerifier.builder().build();
        assertNotNull(verifier);
    }

    @Test
    void builderMethodsReturnBuilder() {
        DefaultConnectionVerifier.Builder builder = DefaultConnectionVerifier.builder();

        assertSame(builder, builder.daneVerifier(mockDaneVerifier));
        assertSame(builder, builder.badgeVerifier(mockBadgeVerifier));
    }

    @Test
    void preVerifyWithNoVerifiers() throws ExecutionException, InterruptedException {
        DefaultConnectionVerifier verifier = DefaultConnectionVerifier.builder().build();

        PreVerificationResult result = verifier.preVerify("test.com", 443).get();

        assertEquals("test.com", result.hostname());
        assertEquals(443, result.port());
        assertFalse(result.hasDaneExpectation());
        assertFalse(result.hasBadgeExpectation());
    }

    @Test
    void preVerifyWithDaneVerifier() throws ExecutionException, InterruptedException {
        byte[] expectedData = "fingerprint".getBytes();
        List<DaneTlsaVerifier.TlsaExpectation> expectations = List.of(
            new DaneTlsaVerifier.TlsaExpectation(1, 1, expectedData));

        when(mockDaneVerifier.preVerify(anyString(), anyInt()))
            .thenReturn(CompletableFuture.completedFuture(DaneVerifier.PreVerifyResult.success(expectations)));

        DefaultConnectionVerifier verifier = DefaultConnectionVerifier.builder()
            .daneVerifier(mockDaneVerifier)
            .build();

        PreVerificationResult result = verifier.preVerify("dane.test.com", 443).get();

        assertTrue(result.hasDaneExpectation());
        assertEquals(1, result.daneExpectations().size());
        assertFalse(result.daneDnsError());
        verify(mockDaneVerifier).preVerify("dane.test.com", 443);
    }

    @Test
    void preVerifyWithBadgeVerifier() throws ExecutionException, InterruptedException {
        BadgeVerifier.BadgeExpectation badgeExpectation = BadgeVerifier.BadgeExpectation.registered(
            List.of("fp1", "fp2"), false, null);

        when(mockBadgeVerifier.preVerify(anyString()))
            .thenReturn(CompletableFuture.completedFuture(badgeExpectation));

        DefaultConnectionVerifier verifier = DefaultConnectionVerifier.builder()
            .badgeVerifier(mockBadgeVerifier)
            .build();

        PreVerificationResult result = verifier.preVerify("badge.test.com", 443).get();

        assertTrue(result.hasBadgeExpectation());
        assertEquals(2, result.badgeFingerprints().size());
        verify(mockBadgeVerifier).preVerify("badge.test.com");
    }

    @Test
    void preVerifyWithBadgePreVerifyFailed() throws ExecutionException, InterruptedException {
        BadgeVerifier.BadgeExpectation badgeExpectation = BadgeVerifier.BadgeExpectation.failed("Certificate revoked");

        when(mockBadgeVerifier.preVerify(anyString()))
            .thenReturn(CompletableFuture.completedFuture(badgeExpectation));

        DefaultConnectionVerifier verifier = DefaultConnectionVerifier.builder()
            .badgeVerifier(mockBadgeVerifier)
            .build();

        PreVerificationResult result = verifier.preVerify("revoked.test.com", 443).get();

        assertTrue(result.badgePreVerifyFailed());
        assertEquals("Certificate revoked", result.badgeFailureReason());
    }

    @Test
    void postVerifyWithNoVerifiers() {
        DefaultConnectionVerifier verifier = DefaultConnectionVerifier.builder().build();
        PreVerificationResult preResult = PreVerificationResult.builder("test.com", 443).build();

        List<VerificationResult> results = verifier.postVerify("test.com", mockCert, preResult);

        assertTrue(results.isEmpty());
    }

    @Test
    void postVerifyWithDaneVerifier() {
        VerificationResult daneResult = VerificationResult.success(
            VerificationResult.VerificationType.DANE, "fp123");

        when(mockDaneVerifier.postVerify(anyString(), any(), any()))
            .thenReturn(daneResult);

        DefaultConnectionVerifier verifier = DefaultConnectionVerifier.builder()
            .daneVerifier(mockDaneVerifier)
            .build();

        PreVerificationResult preResult = PreVerificationResult.builder("test.com", 443).build();
        List<VerificationResult> results = verifier.postVerify("test.com", mockCert, preResult);

        assertEquals(1, results.size());
        assertEquals(VerificationResult.VerificationType.DANE, results.get(0).type());
    }

    @Test
    void postVerifyWithBadgeVerifier() {
        VerificationResult badgeResult = VerificationResult.success(
            VerificationResult.VerificationType.BADGE, "fp456");

        when(mockBadgeVerifier.postVerify(anyString(), any(), any()))
            .thenReturn(badgeResult);

        DefaultConnectionVerifier verifier = DefaultConnectionVerifier.builder()
            .badgeVerifier(mockBadgeVerifier)
            .build();

        PreVerificationResult preResult = PreVerificationResult.builder("test.com", 443)
            .badgeFingerprints(List.of("fp456"))
            .build();
        List<VerificationResult> results = verifier.postVerify("test.com", mockCert, preResult);

        assertEquals(1, results.size());
        assertEquals(VerificationResult.VerificationType.BADGE, results.get(0).type());
    }

    @Test
    void combineWithSuccessResult() {
        DefaultConnectionVerifier verifier = DefaultConnectionVerifier.builder().build();

        List<VerificationResult> results = List.of(
            VerificationResult.success(VerificationResult.VerificationType.DANE, "fp123"));

        VerificationResult combined = verifier.combine(results, VerificationPolicy.DANE_AND_BADGE);

        assertTrue(combined.isSuccess());
    }

    @Test
    void combineWithMismatchAndRequiredMode() {
        DefaultConnectionVerifier verifier = DefaultConnectionVerifier.builder().build();

        List<VerificationResult> results = List.of(
            VerificationResult.mismatch(VerificationResult.VerificationType.DANE, "actual", "expected"));

        VerificationResult combined = verifier.combine(results, VerificationPolicy.DANE_AND_BADGE);

        assertTrue(combined.shouldFail());
        assertEquals(VerificationResult.Status.MISMATCH, combined.status());
    }

    @Test
    void combineWithNotFoundAndRequiredMode() {
        DefaultConnectionVerifier verifier = DefaultConnectionVerifier.builder().build();

        List<VerificationResult> results = List.of(
            VerificationResult.notFound(VerificationResult.VerificationType.DANE, "No TLSA records"));

        VerificationResult combined = verifier.combine(results, VerificationPolicy.DANE_AND_BADGE);

        assertTrue(combined.shouldFail());
        assertEquals(VerificationResult.Status.ERROR, combined.status());
    }

    @Test
    void combineWithEmptyResults() {
        DefaultConnectionVerifier verifier = DefaultConnectionVerifier.builder().build();

        VerificationResult combined = verifier.combine(List.of(), VerificationPolicy.PKI_ONLY);

        assertFalse(combined.shouldFail());
        assertTrue(combined.isNotFound());
    }

    @Test
    void combineWithErrorAndRequiredMode() {
        DefaultConnectionVerifier verifier = DefaultConnectionVerifier.builder().build();

        List<VerificationResult> results = List.of(
            VerificationResult.error(VerificationResult.VerificationType.BADGE, "Connection timeout"));

        VerificationResult combined = verifier.combine(results, VerificationPolicy.BADGE_REQUIRED);

        assertTrue(combined.shouldFail());
        assertEquals(VerificationResult.Status.ERROR, combined.status());
    }

    @Test
    void combineWithMultipleResultsPrefersBadgeSuccess() {
        DefaultConnectionVerifier verifier = DefaultConnectionVerifier.builder().build();

        List<VerificationResult> results = List.of(
            VerificationResult.notFound(VerificationResult.VerificationType.DANE, "No records"),
            VerificationResult.success(VerificationResult.VerificationType.BADGE, "fp123"));

        VerificationResult combined = verifier.combine(results, VerificationPolicy.BADGE_REQUIRED);

        assertTrue(combined.isSuccess());
        assertEquals(VerificationResult.VerificationType.BADGE, combined.type());
    }

    // ==================== DNS Error Handling Tests ====================

    @Test
    void postVerifyReturnsDaneErrorWhenDnsLookupFailed() {
        VerificationResult daneResult = VerificationResult.notFound(
            VerificationResult.VerificationType.DANE, "No TLSA records");

        when(mockDaneVerifier.postVerify(anyString(), any(), any()))
            .thenReturn(daneResult);

        DefaultConnectionVerifier verifier = DefaultConnectionVerifier.builder()
            .daneVerifier(mockDaneVerifier)
            .build();

        PreVerificationResult preResult = PreVerificationResult.builder("test.com", 443)
            .daneDnsError("Connection refused")
            .build();

        List<VerificationResult> results = verifier.postVerify("test.com", mockCert, preResult);

        assertEquals(1, results.size());
        assertEquals(VerificationResult.Status.ERROR, results.get(0).status());
        assertTrue(results.get(0).reason().contains("DNS lookup failed"));
    }

    @Test
    void preVerifyWithDaneVerifierDnsError() throws ExecutionException, InterruptedException {
        when(mockDaneVerifier.preVerify(anyString(), anyInt()))
            .thenReturn(CompletableFuture.completedFuture(
                DaneVerifier.PreVerifyResult.dnsError("Network unreachable")));

        DefaultConnectionVerifier verifier = DefaultConnectionVerifier.builder()
            .daneVerifier(mockDaneVerifier)
            .build();

        PreVerificationResult result = verifier.preVerify("dns.error.com", 443).get();

        assertFalse(result.hasDaneExpectation());
        assertTrue(result.daneDnsError());
        assertEquals("Network unreachable", result.daneDnsErrorMessage());
        verify(mockDaneVerifier).preVerify("dns.error.com", 443);
    }

    @Test
    void combineWithDaneErrorAndRequiredModeReturnsError() {
        DefaultConnectionVerifier verifier = DefaultConnectionVerifier.builder().build();

        List<VerificationResult> results = List.of(
            VerificationResult.error(VerificationResult.VerificationType.DANE, "DNS lookup failed"));

        VerificationResult combined = verifier.combine(results, VerificationPolicy.DANE_AND_BADGE);

        assertTrue(combined.shouldFail());
        assertEquals(VerificationResult.Status.ERROR, combined.status());
    }

    // ==================== SCITT Tests ====================

    @Test
    void scittPreVerifyReturnsNotPresentWhenNoScittVerifier() throws ExecutionException, InterruptedException {
        DefaultConnectionVerifier verifier = DefaultConnectionVerifier.builder().build();

        ScittPreVerifyResult result = verifier.scittPreVerify(Map.of()).get();

        assertFalse(result.isPresent());
    }

    @Test
    void scittPreVerifyDelegatesToScittVerifier() throws ExecutionException, InterruptedException {
        ScittExpectation expectation = ScittExpectation.verified(
            List.of("fp123"), List.of(), "test.ans", Map.of(), null);
        ScittPreVerifyResult expectedResult = ScittPreVerifyResult.verified(
            expectation, mock(ScittReceipt.class), mock(StatusToken.class));

        when(mockScittVerifier.preVerify(any()))
            .thenReturn(CompletableFuture.completedFuture(expectedResult));

        DefaultConnectionVerifier verifier = DefaultConnectionVerifier.builder()
            .scittVerifier(mockScittVerifier)
            .build();

        ScittPreVerifyResult result = verifier.scittPreVerify(
            Map.of("X-SCITT-Receipt", "base64")).get();

        assertTrue(result.isPresent());
        verify(mockScittVerifier).preVerify(any());
    }

    @Test
    void withScittResultCreatesEnhancedPreVerificationResult() {
        PreVerificationResult original = PreVerificationResult.builder("test.com", 443)
            .badgeFingerprints(List.of("badge-fp"))
            .build();

        ScittExpectation expectation = ScittExpectation.verified(
            List.of("scitt-fp"), List.of(), "test.ans", Map.of(), null);
        ScittPreVerifyResult scittResult = ScittPreVerifyResult.verified(
            expectation, mock(ScittReceipt.class), mock(StatusToken.class));

        PreVerificationResult enhanced = original.withScittResult(scittResult);

        assertEquals("test.com", enhanced.hostname());
        assertEquals(443, enhanced.port());
        assertTrue(enhanced.hasBadgeExpectation());
        assertTrue(enhanced.hasScittExpectation());
        assertSame(scittResult, enhanced.scittPreVerifyResult());
    }

    @Test
    void postVerifyWithScittVerifierAndExpectation() {
        VerificationResult scittResult = VerificationResult.success(
            VerificationResult.VerificationType.SCITT, "fp123");

        when(mockScittVerifier.postVerify(anyString(), any(), any()))
            .thenReturn(scittResult);

        DefaultConnectionVerifier verifier = DefaultConnectionVerifier.builder()
            .scittVerifier(mockScittVerifier)
            .build();

        ScittExpectation expectation = ScittExpectation.verified(
            List.of("fp123"), List.of(), "test.ans", Map.of(), null);
        ScittPreVerifyResult scittPreResult = ScittPreVerifyResult.verified(
            expectation, mock(ScittReceipt.class), mock(StatusToken.class));

        PreVerificationResult preResult = PreVerificationResult.builder("test.com", 443)
            .scittPreVerifyResult(scittPreResult)
            .build();

        List<VerificationResult> results = verifier.postVerify("test.com", mockCert, preResult);

        assertEquals(1, results.size());
        assertEquals(VerificationResult.VerificationType.SCITT, results.get(0).type());
        assertTrue(results.get(0).isSuccess());
    }

    @Test
    void postVerifyWithScittVerifierButNoExpectationReturnsNotFound() {
        DefaultConnectionVerifier verifier = DefaultConnectionVerifier.builder()
            .scittVerifier(mockScittVerifier)
            .build();

        PreVerificationResult preResult = PreVerificationResult.builder("test.com", 443).build();

        List<VerificationResult> results = verifier.postVerify("test.com", mockCert, preResult);

        assertEquals(1, results.size());
        assertEquals(VerificationResult.VerificationType.SCITT, results.get(0).type());
        assertTrue(results.get(0).isNotFound());
    }

    // ==================== fromPolicy() factory method tests ====================

    @Test
    void fromPolicyWithPkiOnlyCreatesEmptyVerifier() {
        DefaultConnectionVerifier verifier = DefaultConnectionVerifier.fromPolicy(
            VerificationPolicy.PKI_ONLY, null, null);

        assertNotNull(verifier);
    }

    @Test
    void fromPolicyWithDaneAndBadgeWiresDaneVerifier() {
        DaneTlsaVerifier tlsaVerifier = mock(DaneTlsaVerifier.class);
        TransparencyClient tc = mock(TransparencyClient.class);
        when(tc.getBaseUrl()).thenReturn("https://transparency.test.example.com");

        DefaultConnectionVerifier verifier = DefaultConnectionVerifier.fromPolicy(
            VerificationPolicy.DANE_AND_BADGE, tc, tlsaVerifier);

        assertNotNull(verifier);
    }

    @Test
    void fromPolicyWithBadgeRequiredAndTransparencyClient() {
        TransparencyClient tc = mock(TransparencyClient.class);
        when(tc.getBaseUrl()).thenReturn("https://transparency.test.example.com");

        DefaultConnectionVerifier verifier = DefaultConnectionVerifier.fromPolicy(
            VerificationPolicy.BADGE_REQUIRED, tc, null);

        assertNotNull(verifier);
    }

    @Test
    void fromPolicyWithBadgeRequiredThrowsWithoutTransparencyClient() {
        assertThrows(IllegalStateException.class, () ->
            DefaultConnectionVerifier.fromPolicy(
                VerificationPolicy.BADGE_REQUIRED, null, null));
    }

    @Test
    void fromPolicyWithBadgeServiceOverride() {
        ServerVerifier customService = mock(ServerVerifier.class);

        DefaultConnectionVerifier verifier = DefaultConnectionVerifier.fromPolicy(
            VerificationPolicy.BADGE_REQUIRED, null, null, customService);

        assertNotNull(verifier);
    }

    @Test
    void fromPolicySkipsDaneWhenVerifierNull() {
        // DANE enabled in policy but no verifier provided -- should not throw
        TransparencyClient tc = mock(TransparencyClient.class);
        when(tc.getBaseUrl()).thenReturn("https://transparency.test.example.com");

        DefaultConnectionVerifier verifier = DefaultConnectionVerifier.fromPolicy(
            VerificationPolicy.DANE_AND_BADGE, tc, null);

        assertNotNull(verifier);
    }

    // ==================== Dual Hostname Tests ====================

    private static final String CONNECTION_HOST = "bailian.aliyun.com";
    private static final String IDENTITY_HOST = "abc123.bailian.aliyun.com";
    private static final String ACCESS_HOST = "bailian.aliyun.com";

    @Test
    void preVerifyWithDualHostnameUsesIdentityForBadgeAndAccessForDane()
            throws ExecutionException, InterruptedException {
        when(mockDaneVerifier.preVerify(anyString(), anyInt()))
            .thenReturn(CompletableFuture.completedFuture(DaneVerifier.PreVerifyResult.success(List.of())));
        when(mockBadgeVerifier.preVerify(anyString()))
            .thenReturn(CompletableFuture.completedFuture(
                BadgeVerifier.BadgeExpectation.registered(List.of("fp1"), false, null)));

        DefaultConnectionVerifier verifier = DefaultConnectionVerifier.builder()
            .daneVerifier(mockDaneVerifier)
            .badgeVerifier(mockBadgeVerifier)
            .identityHost(IDENTITY_HOST)
            .accessHost(ACCESS_HOST)
            .build();

        PreVerificationResult result = verifier.preVerify(CONNECTION_HOST, 443).get();

        assertEquals(CONNECTION_HOST, result.hostname());
        verify(mockDaneVerifier).preVerify(ACCESS_HOST, 443);
        verify(mockBadgeVerifier).preVerify(IDENTITY_HOST);
    }

    @Test
    void postVerifyWithDualHostnameUsesIdentityForBadgeAndAccessForDane() {
        VerificationResult daneResult = VerificationResult.success(
            VerificationResult.VerificationType.DANE, "dane-fp");
        VerificationResult badgeResult = VerificationResult.success(
            VerificationResult.VerificationType.BADGE, "badge-fp");

        when(mockDaneVerifier.postVerify(anyString(), any(), any()))
            .thenReturn(daneResult);
        when(mockBadgeVerifier.postVerify(anyString(), any(), any()))
            .thenReturn(badgeResult);

        DefaultConnectionVerifier verifier = DefaultConnectionVerifier.builder()
            .daneVerifier(mockDaneVerifier)
            .badgeVerifier(mockBadgeVerifier)
            .identityHost(IDENTITY_HOST)
            .accessHost(ACCESS_HOST)
            .build();

        PreVerificationResult preResult = PreVerificationResult.builder(CONNECTION_HOST, 443)
            .badgeFingerprints(List.of("badge-fp"))
            .build();

        List<VerificationResult> results = verifier.postVerify(CONNECTION_HOST, mockCert, preResult);

        assertEquals(2, results.size());
        verify(mockDaneVerifier).postVerify(eq(ACCESS_HOST), eq(mockCert), any());
        verify(mockBadgeVerifier).postVerify(eq(IDENTITY_HOST), eq(mockCert), any());
    }

    @Test
    void preVerifyWithoutHostnameOverridesUsesConnectionHost()
            throws ExecutionException, InterruptedException {
        when(mockDaneVerifier.preVerify(anyString(), anyInt()))
            .thenReturn(CompletableFuture.completedFuture(DaneVerifier.PreVerifyResult.success(List.of())));
        when(mockBadgeVerifier.preVerify(anyString()))
            .thenReturn(CompletableFuture.completedFuture(
                BadgeVerifier.BadgeExpectation.notAtiAgent()));

        DefaultConnectionVerifier verifier = DefaultConnectionVerifier.builder()
            .daneVerifier(mockDaneVerifier)
            .badgeVerifier(mockBadgeVerifier)
            .build();

        verifier.preVerify(CONNECTION_HOST, 443).get();

        verify(mockDaneVerifier).preVerify(CONNECTION_HOST, 443);
        verify(mockBadgeVerifier).preVerify(CONNECTION_HOST);
    }

    @Test
    void preVerifyWithOnlyIdentityHostOverrideUsesConnectionHostForDane()
            throws ExecutionException, InterruptedException {
        when(mockDaneVerifier.preVerify(anyString(), anyInt()))
            .thenReturn(CompletableFuture.completedFuture(DaneVerifier.PreVerifyResult.success(List.of())));
        when(mockBadgeVerifier.preVerify(anyString()))
            .thenReturn(CompletableFuture.completedFuture(
                BadgeVerifier.BadgeExpectation.notAtiAgent()));

        DefaultConnectionVerifier verifier = DefaultConnectionVerifier.builder()
            .daneVerifier(mockDaneVerifier)
            .badgeVerifier(mockBadgeVerifier)
            .identityHost(IDENTITY_HOST)
            .build();

        verifier.preVerify(CONNECTION_HOST, 443).get();

        verify(mockDaneVerifier).preVerify(CONNECTION_HOST, 443);
        verify(mockBadgeVerifier).preVerify(IDENTITY_HOST);
    }

    @Test
    void preVerifyWithOnlyAccessHostOverrideUsesConnectionHostForBadge()
            throws ExecutionException, InterruptedException {
        when(mockDaneVerifier.preVerify(anyString(), anyInt()))
            .thenReturn(CompletableFuture.completedFuture(DaneVerifier.PreVerifyResult.success(List.of())));
        when(mockBadgeVerifier.preVerify(anyString()))
            .thenReturn(CompletableFuture.completedFuture(
                BadgeVerifier.BadgeExpectation.notAtiAgent()));

        DefaultConnectionVerifier verifier = DefaultConnectionVerifier.builder()
            .daneVerifier(mockDaneVerifier)
            .badgeVerifier(mockBadgeVerifier)
            .accessHost(ACCESS_HOST)
            .build();

        verifier.preVerify(CONNECTION_HOST, 443).get();

        verify(mockDaneVerifier).preVerify(ACCESS_HOST, 443);
        verify(mockBadgeVerifier).preVerify(CONNECTION_HOST);
    }

    @Test
    void preVerifyWithBlankHostnameOverridesFallsBackToConnectionHost()
            throws ExecutionException, InterruptedException {
        when(mockDaneVerifier.preVerify(anyString(), anyInt()))
            .thenReturn(CompletableFuture.completedFuture(DaneVerifier.PreVerifyResult.success(List.of())));
        when(mockBadgeVerifier.preVerify(anyString()))
            .thenReturn(CompletableFuture.completedFuture(
                BadgeVerifier.BadgeExpectation.notAtiAgent()));

        DefaultConnectionVerifier verifier = DefaultConnectionVerifier.builder()
            .daneVerifier(mockDaneVerifier)
            .badgeVerifier(mockBadgeVerifier)
            .identityHost("   ")
            .accessHost("")
            .build();

        verifier.preVerify(CONNECTION_HOST, 443).get();

        verify(mockDaneVerifier).preVerify(CONNECTION_HOST, 443);
        verify(mockBadgeVerifier).preVerify(CONNECTION_HOST);
    }

    @Test
    void fromPolicyWithDualHostnameRoutesPreVerifyToCorrectHosts()
            throws Exception {
        DaneTlsaVerifier tlsaVerifier = mock(DaneTlsaVerifier.class);
        ServerVerifier serverVerifier = mock(ServerVerifier.class);

        when(tlsaVerifier.getTlsaExpectations(ACCESS_HOST, 443)).thenReturn(List.of());
        when(serverVerifier.verifyServer(IDENTITY_HOST))
            .thenReturn(ServerVerificationResult.builder()
                .status(VerificationStatus.NOT_ATI_AGENT)
                .build());

        DefaultConnectionVerifier verifier = DefaultConnectionVerifier.fromPolicy(
            VerificationPolicy.DANE_AND_BADGE,
            null,
            tlsaVerifier,
            serverVerifier,
            IDENTITY_HOST,
            ACCESS_HOST);

        verifier.preVerify(CONNECTION_HOST, 443).get();

        verify(tlsaVerifier).getTlsaExpectations(ACCESS_HOST, 443);
        verify(tlsaVerifier, never()).getTlsaExpectations(IDENTITY_HOST, 443);
        verify(serverVerifier).verifyServer(IDENTITY_HOST);
        verify(serverVerifier, never()).verifyServer(ACCESS_HOST);
    }
}
