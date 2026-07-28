package com.aliyun.ati.sdk.agent.verification;

import com.aliyun.ati.sdk.agent.VerificationPolicy;
import com.aliyun.ati.sdk.transparency.verification.ServerVerificationResult;
import com.aliyun.ati.sdk.transparency.verification.ServerVerifier;
import com.aliyun.ati.sdk.transparency.verification.VerificationStatus;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.ExecutionException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Dual-hostname routing tests for {@link DefaultConnectionVerifier}.
 */
class DefaultConnectionVerifierDualHostnameTest {

    private static final String CONNECTION_HOST = "bailian.aliyun.com";
    private static final String IDENTITY_HOST = "abc123.bailian.aliyun.com";
    private static final String ACCESS_HOST = "bailian.aliyun.com";

    private DaneVerifier mockDaneVerifier;
    private BadgeVerifier mockBadgeVerifier;
    private X509Certificate mockCert;

    @BeforeEach
    void setUp() {
        mockDaneVerifier = mock(DaneVerifier.class);
        mockBadgeVerifier = mock(BadgeVerifier.class);
        mockCert = mock(X509Certificate.class);
    }

    @Test
    void preVerifyWithDualHostnameUsesIdentityForBadgeAndAccessForDane()
            throws ExecutionException, InterruptedException {
        when(mockDaneVerifier.preVerify(anyString(), anyInt()))
            .thenReturn(java.util.concurrent.CompletableFuture.completedFuture(
                DaneVerifier.PreVerifyResult.success(List.of())));
        when(mockBadgeVerifier.preVerify(anyString()))
            .thenReturn(java.util.concurrent.CompletableFuture.completedFuture(
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
            .thenReturn(java.util.concurrent.CompletableFuture.completedFuture(
                DaneVerifier.PreVerifyResult.success(List.of())));
        when(mockBadgeVerifier.preVerify(anyString()))
            .thenReturn(java.util.concurrent.CompletableFuture.completedFuture(
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
            .thenReturn(java.util.concurrent.CompletableFuture.completedFuture(
                DaneVerifier.PreVerifyResult.success(List.of())));
        when(mockBadgeVerifier.preVerify(anyString()))
            .thenReturn(java.util.concurrent.CompletableFuture.completedFuture(
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
            .thenReturn(java.util.concurrent.CompletableFuture.completedFuture(
                DaneVerifier.PreVerifyResult.success(List.of())));
        when(mockBadgeVerifier.preVerify(anyString()))
            .thenReturn(java.util.concurrent.CompletableFuture.completedFuture(
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
            .thenReturn(java.util.concurrent.CompletableFuture.completedFuture(
                DaneVerifier.PreVerifyResult.success(List.of())));
        when(mockBadgeVerifier.preVerify(anyString()))
            .thenReturn(java.util.concurrent.CompletableFuture.completedFuture(
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
            VerificationPolicy.ADVANCED,
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
