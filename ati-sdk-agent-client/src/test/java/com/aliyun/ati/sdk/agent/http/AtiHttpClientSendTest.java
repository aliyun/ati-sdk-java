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
import java.util.concurrent.ExecutionException;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Tests for AtiHttpClient.
 */
class AtiHttpClientSendTest {

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
    @SuppressWarnings("unchecked")
    void sendWithVerificationSuccessShouldReturnResponse() throws Exception {
        X509Certificate mockCert = mock(X509Certificate.class);
        X509Certificate[] certs = new X509Certificate[]{mockCert};

        when(mockCertProvider.getCapturedCertificates("example.com")).thenReturn(certs);

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockResponse.body()).thenReturn("success");
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(mockResponse);

        PreVerificationResult preResult = PreVerificationResult.builder("example.com", 443).build();
        when(mockVerifier.preVerify(anyString(), anyInt()))
            .thenReturn(CompletableFuture.completedFuture(preResult));

        VerificationResult successResult = VerificationResult.success(
            VerificationResult.VerificationType.DANE, "fp123");
        when(mockVerifier.postVerify(anyString(), any(), any()))
            .thenReturn(List.of(successResult));
        when(mockVerifier.combine(any(), any()))
            .thenReturn(successResult);

        AtiHttpClient client = AtiHttpClient.builder()
            .delegate(mockHttpClient)
            .connectionVerifier(mockVerifier)
            .verificationPolicy(VerificationPolicy.ADVANCED)
            .certProvider(mockCertProvider)
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api"))
            .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        assertNotNull(response);
        assertEquals("success", response.body());
        verify(mockCertProvider).clearCapturedCertificates("example.com");
    }

    @Test
    @SuppressWarnings("unchecked")
    void sendWithVerificationFailureShouldThrowException() throws Exception {
        X509Certificate mockCert = mock(X509Certificate.class);
        X509Certificate[] certs = new X509Certificate[]{mockCert};

        when(mockCertProvider.getCapturedCertificates("example.com")).thenReturn(certs);

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(mockResponse);

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

        assertThrows(VerificationException.class, () ->
            client.send(request, HttpResponse.BodyHandlers.ofString()));

        verify(mockVerifier, times(2)).preVerify("example.com", 443);
    }

    @Test
    @SuppressWarnings("unchecked")
    void sendWithNoCapturedCertificatesShouldThrowWhenVerificationRequired() throws Exception {
        when(mockCertProvider.getCapturedCertificates("example.com")).thenReturn(null);

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(mockResponse);

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

        assertThrows(VerificationException.class, () ->
            client.send(request, HttpResponse.BodyHandlers.ofString()));
    }

    @Test
    @SuppressWarnings("unchecked")
    void sendWithNoCertificatesAndPkiOnlyShouldSucceed() throws Exception {
        when(mockCertProvider.getCapturedCertificates("example.com")).thenReturn(null);

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockResponse.body()).thenReturn("success");
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(mockResponse);

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

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        assertNotNull(response);
    }

    @Test
    @SuppressWarnings("unchecked")
    void sendWithBadgePreVerificationFailedShouldThrowWhenRequired() throws Exception {
        PreVerificationResult preResult = PreVerificationResult.builder("example.com", 443)
            .badgePreVerifyFailed("Certificate revoked")
            .build();
        when(mockVerifier.preVerify(anyString(), anyInt()))
            .thenReturn(CompletableFuture.completedFuture(preResult));

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
        assertTrue(ex.getMessage().contains("BADGE"));
    }

    @Test
    @SuppressWarnings("unchecked")
    void sendAsyncWithVerificationSuccessShouldReturnResponse() throws Exception {
        X509Certificate mockCert = mock(X509Certificate.class);
        X509Certificate[] certs = new X509Certificate[]{mockCert};

        when(mockCertProvider.getCapturedCertificates("example.com")).thenReturn(certs);

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockResponse.body()).thenReturn("async success");
        when(mockHttpClient.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(CompletableFuture.completedFuture(mockResponse));

        PreVerificationResult preResult = PreVerificationResult.builder("example.com", 443).build();
        when(mockVerifier.preVerify(anyString(), anyInt()))
            .thenReturn(CompletableFuture.completedFuture(preResult));

        VerificationResult successResult = VerificationResult.success(
            VerificationResult.VerificationType.BADGE, "fp456");
        when(mockVerifier.postVerify(anyString(), any(), any()))
            .thenReturn(List.of(successResult));
        when(mockVerifier.combine(any(), any()))
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
        assertEquals("async success", response.body());
    }

    @Test
    void sendAsyncWithBadgePreVerificationFailedShouldFail() {
        PreVerificationResult preResult = PreVerificationResult.builder("example.com", 443)
            .badgePreVerifyFailed("Expired registration")
            .build();
        when(mockVerifier.preVerify(anyString(), anyInt()))
            .thenReturn(CompletableFuture.completedFuture(preResult));

        AtiHttpClient client = AtiHttpClient.builder()
            .delegate(mockHttpClient)
            .connectionVerifier(mockVerifier)
            .verificationPolicy(VerificationPolicy.ENHANCED)
            .certProvider(mockCertProvider)
            .build();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api"))
            .build();

        CompletableFuture<HttpResponse<String>> future =
            client.sendAsync(request, HttpResponse.BodyHandlers.ofString());

        ExecutionException ex = assertThrows(ExecutionException.class, future::get);
        assertTrue(ex.getCause() instanceof VerificationException);
    }

    @Test
    void sendWithCustomPortShouldUseCorrectPort() throws Exception {
        X509Certificate mockCert = mock(X509Certificate.class);
        X509Certificate[] certs = new X509Certificate[]{mockCert};

        when(mockCertProvider.getCapturedCertificates("example.com")).thenReturn(certs);

        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(mockResponse);

        PreVerificationResult preResult = PreVerificationResult.builder("example.com", 8443).build();
        when(mockVerifier.preVerify(eq("example.com"), eq(8443)))
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
            .uri(URI.create("https://example.com:8443/api"))
            .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        assertNotNull(response);
    }

    @Test
    void noVerificationClientSendDelegatesToHttpClient() throws Exception {
        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockResponse.body()).thenReturn("direct");
        when(mockHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(mockResponse);

        AtiHttpClient client = AtiHttpClient.noVerification(mockHttpClient);

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api"))
            .build();

        HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());

        assertNotNull(response);
        assertEquals("direct", response.body());
    }

    @Test
    void noVerificationClientSendAsyncDelegatesToHttpClient() throws Exception {
        HttpResponse<String> mockResponse = mock(HttpResponse.class);
        when(mockResponse.body()).thenReturn("async direct");
        when(mockHttpClient.sendAsync(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(CompletableFuture.completedFuture(mockResponse));

        AtiHttpClient client = AtiHttpClient.noVerification(mockHttpClient);

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://example.com/api"))
            .build();

        HttpResponse<String> response = client.sendAsync(request, HttpResponse.BodyHandlers.ofString()).get();

        assertNotNull(response);
        assertEquals("async direct", response.body());
    }

}
