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
import java.time.Duration;
import java.util.List;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutionException;

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
class AtiHttpClientSendAsyncTest {

    private HttpClient mockHttpClient;
    private ConnectionVerifier mockVerifier;
    private CapturedCertificateProvider mockCertProvider;

    @BeforeEach
    void setUp() {
        mockHttpClient = mock(HttpClient.class);
        mockVerifier = mock(ConnectionVerifier.class);
        mockCertProvider = mock(CapturedCertificateProvider.class);
    }
    @Test
    void preVerifyCacheIsUsedOnSubsequentCalls() throws Exception {
        X509Certificate mockCert = mock(X509Certificate.class);
        X509Certificate[] certs = new X509Certificate[]{mockCert};

        when(mockCertProvider.getCapturedCertificates("example.com")).thenReturn(certs);

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(mockResponse);

        PreVerificationResult preResult = PreVerificationResult.builder("example.com", 443).build();
        when(mockVerifier.preVerify(anyString(), anyInt()))
            .thenReturn(CompletableFuture.completedFuture(preResult));

        VerificationResult successResult = VerificationResult.skipped("PKI only");
        when(mockVerifier.postVerify(anyString(), any(), any()))
            .thenReturn(List.of(successResult));
        when(mockVerifier.combine(any(), any()))
            .thenReturn(successResult);

        AtiHttpClient client = AtiHttpClient.builder()
            .delegate(mockHttpClient)
            .connectionVerifier(mockVerifier)
            .verificationPolicy(VerificationPolicy.BASIC)
            .certProvider(mockCertProvider)
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api"))
            .build();

        client.send(request, HttpResponse.BodyHandlers.ofString());
        client.send(request, HttpResponse.BodyHandlers.ofString());

        verify(mockVerifier, times(1)).preVerify("example.com", 443);
    }

    @Test
    void clearCacheAllowsNewPreVerification() throws Exception {
        X509Certificate mockCert = mock(X509Certificate.class);
        X509Certificate[] certs = new X509Certificate[]{mockCert};

        when(mockCertProvider.getCapturedCertificates("example.com")).thenReturn(certs);

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(mockResponse);

        PreVerificationResult preResult = PreVerificationResult.builder("example.com", 443).build();
        when(mockVerifier.preVerify(anyString(), anyInt()))
            .thenReturn(CompletableFuture.completedFuture(preResult));

        VerificationResult successResult = VerificationResult.skipped("PKI only");
        when(mockVerifier.postVerify(anyString(), any(), any()))
            .thenReturn(List.of(successResult));
        when(mockVerifier.combine(any(), any()))
            .thenReturn(successResult);

        AtiHttpClient client = AtiHttpClient.builder()
            .delegate(mockHttpClient)
            .connectionVerifier(mockVerifier)
            .verificationPolicy(VerificationPolicy.BASIC)
            .certProvider(mockCertProvider)
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api"))
            .build();

        client.send(request, HttpResponse.BodyHandlers.ofString());
        client.clearCache();
        client.send(request, HttpResponse.BodyHandlers.ofString());

        verify(mockVerifier, times(2)).preVerify("example.com", 443);
    }

    @Test
    void invalidateCacheForSpecificHostAllowsNewPreVerification() throws Exception {
        X509Certificate mockCert = mock(X509Certificate.class);
        X509Certificate[] certs = new X509Certificate[]{mockCert};

        when(mockCertProvider.getCapturedCertificates("example.com")).thenReturn(certs);

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(mockResponse);

        PreVerificationResult preResult = PreVerificationResult.builder("example.com", 443).build();
        when(mockVerifier.preVerify(anyString(), anyInt()))
            .thenReturn(CompletableFuture.completedFuture(preResult));

        VerificationResult successResult = VerificationResult.skipped("PKI only");
        when(mockVerifier.postVerify(anyString(), any(), any()))
            .thenReturn(List.of(successResult));
        when(mockVerifier.combine(any(), any()))
            .thenReturn(successResult);

        AtiHttpClient client = AtiHttpClient.builder()
            .delegate(mockHttpClient)
            .connectionVerifier(mockVerifier)
            .verificationPolicy(VerificationPolicy.BASIC)
            .certProvider(mockCertProvider)
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api"))
            .build();

        client.send(request, HttpResponse.BodyHandlers.ofString());
        client.invalidateCache("example.com", 443);
        client.send(request, HttpResponse.BodyHandlers.ofString());

        verify(mockVerifier, times(2)).preVerify("example.com", 443);
    }

    @Test
    @SuppressWarnings("unchecked")
    void sendAsyncWithPreVerificationTimeoutFallsBackToEmptyResult() throws Exception {
        CompletableFuture<PreVerificationResult> slowFuture = new CompletableFuture<>();

        when(mockVerifier.preVerify(anyString(), anyInt()))
            .thenReturn(slowFuture);

        X509Certificate mockCert = mock(X509Certificate.class);
        X509Certificate[] certs = new X509Certificate[]{mockCert};

        when(mockCertProvider.getCapturedCertificates("example.com")).thenReturn(certs);

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockResponse.body()).thenReturn("success");
        when(mockHttpClient.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(CompletableFuture.completedFuture(mockResponse));

        VerificationResult successResult = VerificationResult.skipped("PKI only");
        when(mockVerifier.postVerify(anyString(), any(), any()))
            .thenReturn(List.of(successResult));
        when(mockVerifier.combine(any(), any()))
            .thenReturn(successResult);

        AtiHttpClient client = AtiHttpClient.builder()
            .delegate(mockHttpClient)
            .connectionVerifier(mockVerifier)
            .verificationPolicy(VerificationPolicy.BASIC)
            .certProvider(mockCertProvider)
            .preVerifyTimeout(Duration.ofMillis(100))
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api"))
            .build();

        HttpResponse<String> response = client.sendAsync(request, HttpResponse.BodyHandlers.ofString()).get();

        assertNotNull(response);
        assertEquals("success", response.body());
    }

    @Test
    @SuppressWarnings("unchecked")
    void sendAsyncWithNoCapturedCertificatesShouldFailWhenRequired() {
        when(mockCertProvider.getCapturedCertificates("example.com")).thenReturn(null);

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockHttpClient.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(CompletableFuture.completedFuture(mockResponse));

        PreVerificationResult preResult = PreVerificationResult.builder("example.com", 443).build();
        when(mockVerifier.preVerify(anyString(), anyInt()))
            .thenReturn(CompletableFuture.completedFuture(preResult));

        AtiHttpClient client = AtiHttpClient.builder()
            .delegate(mockHttpClient)
            .connectionVerifier(mockVerifier)
            .verificationPolicy(VerificationPolicy.ADVANCED)
            .certProvider(mockCertProvider)
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api"))
            .build();

        CompletableFuture<HttpResponse<String>> future =
            client.sendAsync(request, HttpResponse.BodyHandlers.ofString());

        ExecutionException ex = assertThrows(ExecutionException.class, future::get);
        assertTrue(ex.getCause() instanceof VerificationException);
        assertTrue(ex.getCause().getMessage().contains("No certificates captured"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void sendAsyncWithVerificationFailureShouldThrowException() {
        X509Certificate mockCert = mock(X509Certificate.class);
        X509Certificate[] certs = new X509Certificate[]{mockCert};

        when(mockCertProvider.getCapturedCertificates("example.com")).thenReturn(certs);

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockHttpClient.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(CompletableFuture.completedFuture(mockResponse));

        PreVerificationResult preResult = PreVerificationResult.builder("example.com", 443).build();
        when(mockVerifier.preVerify(anyString(), anyInt()))
            .thenReturn(CompletableFuture.completedFuture(preResult));

        VerificationResult failResult = VerificationResult.mismatch(
            VerificationResult.VerificationType.DANE, "actual", "expected");
        when(mockVerifier.postVerify(anyString(), any(), any()))
            .thenReturn(List.of(failResult));
        when(mockVerifier.combine(any(), any()))
            .thenReturn(failResult);

        AtiHttpClient client = AtiHttpClient.builder()
            .delegate(mockHttpClient)
            .connectionVerifier(mockVerifier)
            .verificationPolicy(VerificationPolicy.ADVANCED)
            .certProvider(mockCertProvider)
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api"))
            .build();

        CompletableFuture<HttpResponse<String>> future =
            client.sendAsync(request, HttpResponse.BodyHandlers.ofString());

        ExecutionException ex = assertThrows(ExecutionException.class, future::get);
        assertTrue(ex.getCause() instanceof VerificationException);

        verify(mockVerifier, times(2)).preVerify("example.com", 443);
    }

    @Test
    @SuppressWarnings("unchecked")
    void sendWithPreVerifyExceptionFallsBackToEmptyResult() throws Exception {
        when(mockVerifier.preVerify(anyString(), anyInt()))
            .thenReturn(CompletableFuture.failedFuture(new RuntimeException("DNS lookup failed")));

        X509Certificate mockCert = mock(X509Certificate.class);
        X509Certificate[] certs = new X509Certificate[]{mockCert};

        when(mockCertProvider.getCapturedCertificates("example.com")).thenReturn(certs);

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockResponse.body()).thenReturn("success after fallback");
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(mockResponse);

        VerificationResult successResult = VerificationResult.skipped("PKI only");
        when(mockVerifier.postVerify(anyString(), any(), any()))
            .thenReturn(List.of(successResult));
        when(mockVerifier.combine(any(), any()))
            .thenReturn(successResult);

        AtiHttpClient client = AtiHttpClient.builder()
            .delegate(mockHttpClient)
            .connectionVerifier(mockVerifier)
            .verificationPolicy(VerificationPolicy.BASIC)
            .certProvider(mockCertProvider)
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api"))
            .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        assertNotNull(response);
        assertEquals("success after fallback", response.body());
    }

    @Test
    @SuppressWarnings("unchecked")
    void sendAsyncWithNoCapturedCertsAndPkiOnlyShouldSucceed() throws Exception {
        when(mockCertProvider.getCapturedCertificates("example.com")).thenReturn(null);

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockResponse.body()).thenReturn("pki only success");
        when(mockHttpClient.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(CompletableFuture.completedFuture(mockResponse));

        PreVerificationResult preResult = PreVerificationResult.builder("example.com", 443).build();
        when(mockVerifier.preVerify(anyString(), anyInt()))
            .thenReturn(CompletableFuture.completedFuture(preResult));

        AtiHttpClient client = AtiHttpClient.builder()
            .delegate(mockHttpClient)
            .connectionVerifier(mockVerifier)
            .verificationPolicy(VerificationPolicy.BASIC)
            .certProvider(mockCertProvider)
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api"))
            .build();

        HttpResponse<String> response = client.sendAsync(request, HttpResponse.BodyHandlers.ofString()).get();

        assertNotNull(response);
        assertEquals("pki only success", response.body());
    }

}
