package com.aliyun.ati.sdk.agent.http;

import com.aliyun.ati.sdk.agent.VerificationPolicy;
import com.aliyun.ati.sdk.agent.exception.VerificationException;
import com.aliyun.ati.sdk.agent.verification.ConnectionVerifier;
import com.aliyun.ati.sdk.agent.verification.PreVerificationResult;
import com.aliyun.ati.sdk.agent.verification.VerificationResult;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.concurrent.CompletableFuture;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for AtiHttpClient.
 */
class AtiHttpClientRetryTest {

    private HttpClient mockHttpClient;
    private ConnectionVerifier mockVerifier;
    private CapturedCertificateProvider mockCertProvider;

    @BeforeEach
    void setUp() {
        mockHttpClient = mock(HttpClient.class);
        mockVerifier = mock(ConnectionVerifier.class);
        mockCertProvider = mock(CapturedCertificateProvider.class);
    }
    // ==================== Retry on Mismatch Tests ====================

    @Test
    @SuppressWarnings("unchecked")
    void sendWithMismatchShouldRetryAndSucceedWithFreshData() throws Exception {
        X509Certificate mockCert = mock(X509Certificate.class);
        X509Certificate[] certs = new X509Certificate[]{mockCert};

        when(mockCertProvider.getCapturedCertificates("example.com")).thenReturn(certs);

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockResponse.body()).thenReturn("success after retry");
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(mockResponse);

        PreVerificationResult stalePreResult = PreVerificationResult.builder("example.com", 443)
            .badgeFingerprints(List.of("old-fingerprint"))
            .build();
        PreVerificationResult freshPreResult = PreVerificationResult.builder("example.com", 443)
            .badgeFingerprints(List.of("new-fingerprint"))
            .build();
        when(mockVerifier.preVerify(anyString(), anyInt()))
            .thenReturn(CompletableFuture.completedFuture(stalePreResult))
            .thenReturn(CompletableFuture.completedFuture(freshPreResult));

        VerificationResult mismatchResult = VerificationResult.mismatch(
            VerificationResult.VerificationType.BADGE, "actual-fp", "old-fingerprint");
        VerificationResult successResult = VerificationResult.success(
            VerificationResult.VerificationType.BADGE, "actual-fp");

        when(mockVerifier.postVerify(anyString(), any(), any()))
            .thenReturn(List.of(mismatchResult))
            .thenReturn(List.of(successResult));

        when(mockVerifier.combine(any(), any()))
            .thenReturn(mismatchResult)
            .thenReturn(successResult);

        AtiHttpClient client = AtiHttpClient.builder()
            .delegate(mockHttpClient)
            .connectionVerifier(mockVerifier)
            .verificationPolicy(VerificationPolicy.ENHANCED)
            .certProvider(mockCertProvider)
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api"))
            .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        assertNotNull(response);
        assertEquals("success after retry", response.body());
        verify(mockVerifier, times(2)).preVerify("example.com", 443);
    }

    @Test
    @SuppressWarnings("unchecked")
    void sendWithMismatchShouldThrowAfterRetryIfStillMismatch() throws Exception {
        X509Certificate mockCert = mock(X509Certificate.class);
        X509Certificate[] certs = new X509Certificate[]{mockCert};

        when(mockCertProvider.getCapturedCertificates("example.com")).thenReturn(certs);

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(mockResponse);

        PreVerificationResult preResult = PreVerificationResult.builder("example.com", 443)
            .badgeFingerprints(List.of("expected-fp"))
            .build();
        when(mockVerifier.preVerify(anyString(), anyInt()))
            .thenReturn(CompletableFuture.completedFuture(preResult));

        VerificationResult mismatchResult = VerificationResult.mismatch(
            VerificationResult.VerificationType.BADGE, "actual-fp", "expected-fp");
        when(mockVerifier.postVerify(anyString(), any(), any()))
            .thenReturn(List.of(mismatchResult));
        when(mockVerifier.combine(any(), any()))
            .thenReturn(mismatchResult);

        AtiHttpClient client = AtiHttpClient.builder()
            .delegate(mockHttpClient)
            .connectionVerifier(mockVerifier)
            .verificationPolicy(VerificationPolicy.ENHANCED)
            .certProvider(mockCertProvider)
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api"))
            .build();

        VerificationException ex = assertThrows(VerificationException.class, () ->
            client.send(request, HttpResponse.BodyHandlers.ofString()));
        assertTrue(ex.getMessage().contains("mismatch") || ex.getMessage().contains("MISMATCH"));
        verify(mockVerifier, times(2)).preVerify("example.com", 443);
    }

    @Test
    @SuppressWarnings("unchecked")
    void sendWithErrorShouldNotRetry() throws Exception {
        X509Certificate mockCert = mock(X509Certificate.class);
        X509Certificate[] certs = new X509Certificate[]{mockCert};

        when(mockCertProvider.getCapturedCertificates("example.com")).thenReturn(certs);

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(mockResponse);

        PreVerificationResult preResult = PreVerificationResult.builder("example.com", 443).build();
        when(mockVerifier.preVerify(anyString(), anyInt()))
            .thenReturn(CompletableFuture.completedFuture(preResult));

        VerificationResult errorResult = VerificationResult.error(
            VerificationResult.VerificationType.DANE, "DNS resolution failed");
        when(mockVerifier.postVerify(anyString(), any(), any()))
            .thenReturn(List.of(errorResult));
        when(mockVerifier.combine(any(), any()))
            .thenReturn(errorResult);

        AtiHttpClient client = AtiHttpClient.builder()
            .delegate(mockHttpClient)
            .connectionVerifier(mockVerifier)
            .verificationPolicy(VerificationPolicy.ADVANCED)
            .certProvider(mockCertProvider)
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api"))
            .build();

        assertThrows(VerificationException.class, () ->
            client.send(request, HttpResponse.BodyHandlers.ofString()));

        verify(mockVerifier, times(1)).preVerify("example.com", 443);
    }

    @Test
    @SuppressWarnings("unchecked")
    void sendAsyncWithMismatchShouldRetryAndSucceedWithFreshData() throws Exception {
        X509Certificate mockCert = mock(X509Certificate.class);
        X509Certificate[] certs = new X509Certificate[]{mockCert};

        when(mockCertProvider.getCapturedCertificates("example.com")).thenReturn(certs);

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockResponse.body()).thenReturn("async success after retry");
        when(mockHttpClient.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(CompletableFuture.completedFuture(mockResponse));

        PreVerificationResult stalePreResult = PreVerificationResult.builder("example.com", 443)
            .badgeFingerprints(List.of("old-fingerprint"))
            .build();
        PreVerificationResult freshPreResult = PreVerificationResult.builder("example.com", 443)
            .badgeFingerprints(List.of("new-fingerprint"))
            .build();
        when(mockVerifier.preVerify(anyString(), anyInt()))
            .thenReturn(CompletableFuture.completedFuture(stalePreResult))
            .thenReturn(CompletableFuture.completedFuture(freshPreResult));

        VerificationResult mismatchResult = VerificationResult.mismatch(
            VerificationResult.VerificationType.BADGE, "actual-fp", "old-fingerprint");
        VerificationResult successResult = VerificationResult.success(
            VerificationResult.VerificationType.BADGE, "actual-fp");

        when(mockVerifier.postVerify(anyString(), any(), any()))
            .thenReturn(List.of(mismatchResult))
            .thenReturn(List.of(successResult));

        when(mockVerifier.combine(any(), any()))
            .thenReturn(mismatchResult)
            .thenReturn(successResult);

        AtiHttpClient client = AtiHttpClient.builder()
            .delegate(mockHttpClient)
            .connectionVerifier(mockVerifier)
            .verificationPolicy(VerificationPolicy.ENHANCED)
            .certProvider(mockCertProvider)
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api"))
            .build();

        HttpResponse<String> response = client.sendAsync(request, HttpResponse.BodyHandlers.ofString()).get();

        assertNotNull(response);
        assertEquals("async success after retry", response.body());
        verify(mockVerifier, times(2)).preVerify("example.com", 443);
    }
}
