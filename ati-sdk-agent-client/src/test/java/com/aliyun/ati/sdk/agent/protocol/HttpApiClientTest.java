package com.aliyun.ati.sdk.agent.protocol;

import com.aliyun.ati.sdk.agent.exception.ProtocolException;
import com.aliyun.ati.sdk.agent.http.AtiHttpClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.IOException;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class HttpApiClientTest {

    @Mock
    private AtiHttpClient ansHttpClient;

    @Mock
    private HttpResponse<String> httpResponse;

    private HttpApiClient client;

    @BeforeEach
    void setUp() {
        client = new HttpApiClient(ansHttpClient, "https://example.com");
    }

    @Test
    void constructorWithValidParametersShouldSucceed() {
        // Given/When
        HttpApiClient client = new HttpApiClient(ansHttpClient, "https://example.com");

        // Then
        assertThat(client.getBaseUrl()).isEqualTo("https://example.com");
        assertThat(client.getTimeout()).isEqualTo(Duration.ofSeconds(30));
    }

    @Test
    void constructorWithTrailingSlashShouldNormalize() {
        // Given/When
        HttpApiClient client = new HttpApiClient(ansHttpClient, "https://example.com/");

        // Then
        assertThat(client.getBaseUrl()).isEqualTo("https://example.com");
    }

    @Test
    void constructorWithCustomTimeoutShouldSetTimeout() {
        // Given/When
        HttpApiClient client = new HttpApiClient(ansHttpClient, "https://example.com",
            Duration.ofMinutes(5));

        // Then
        assertThat(client.getTimeout()).isEqualTo(Duration.ofMinutes(5));
    }

    @Test
    void constructorWithNullHttpClientShouldThrowException() {
        assertThatThrownBy(() -> new HttpApiClient(null, "https://example.com"))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("HTTP client");
    }

    @Test
    void constructorWithNullBaseUrlShouldThrowException() {
        assertThatThrownBy(() -> new HttpApiClient(ansHttpClient, null))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("Base URL");
    }

    @Test
    @SuppressWarnings("unchecked")
    void getWithSuccessfulResponseShouldReturnBody() throws Exception {
        // Given
        when(ansHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(httpResponse);
        when(httpResponse.statusCode()).thenReturn(200);
        when(httpResponse.body()).thenReturn("{\"data\":\"test\"}");

        // When
        String result = client.get("/api/v1/data");

        // Then
        assertThat(result).isEqualTo("{\"data\":\"test\"}");
    }

    @Test
    @SuppressWarnings("unchecked")
    void getWithTypedResponseShouldDeserialize() throws Exception {
        // Given - response body is read as string first, then deserialized
        when(ansHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(httpResponse);
        when(httpResponse.statusCode()).thenReturn(200);
        when(httpResponse.body()).thenReturn("{\"value\":\"hello\"}");

        // When
        TestResponse result = client.get("/api/v1/data", TestResponse.class);

        // Then
        assertThat(result.value).isEqualTo("hello");
    }

    @Test
    @SuppressWarnings("unchecked")
    void getWith404ResponseShouldThrowProtocolException() throws Exception {
        // Given
        HttpHeaders headers = mock(HttpHeaders.class);
        when(headers.firstValue("X-Request-Id")).thenReturn(java.util.Optional.of("req-123"));

        when(ansHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(httpResponse);
        when(httpResponse.statusCode()).thenReturn(404);
        when(httpResponse.body()).thenReturn("Not Found");
        when(httpResponse.headers()).thenReturn(headers);

        // When/Then
        assertThatThrownBy(() -> client.get("/api/v1/data"))
            .isInstanceOf(ProtocolException.class)
            .hasMessageContaining("not found")
            .extracting("statusCode")
            .isEqualTo(404);
    }

    @Test
    @SuppressWarnings("unchecked")
    void getWith401ResponseShouldThrowAuthException() throws Exception {
        // Given
        HttpHeaders headers = mock(HttpHeaders.class);
        when(headers.firstValue("X-Request-Id")).thenReturn(java.util.Optional.empty());

        when(ansHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(httpResponse);
        when(httpResponse.statusCode()).thenReturn(401);
        when(httpResponse.body()).thenReturn("Unauthorized");
        when(httpResponse.headers()).thenReturn(headers);

        // When/Then
        assertThatThrownBy(() -> client.get("/api/v1/data"))
            .isInstanceOf(ProtocolException.class)
            .hasMessageContaining("Authentication");
    }

    @Test
    @SuppressWarnings("unchecked")
    void postWithSuccessfulResponseShouldReturnBody() throws Exception {
        // Given
        when(ansHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(httpResponse);
        when(httpResponse.statusCode()).thenReturn(201);
        when(httpResponse.body()).thenReturn("{\"id\":\"123\"}");

        // When
        String result = client.post("/api/v1/data", new TestRequest("hello"));

        // Then
        assertThat(result).contains("123");
    }

    @Test
    @SuppressWarnings("unchecked")
    void putWithSuccessfulResponseShouldReturnBody() throws Exception {
        // Given
        when(ansHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(httpResponse);
        when(httpResponse.statusCode()).thenReturn(200);
        when(httpResponse.body()).thenReturn("{\"updated\":true}");

        // When
        String result = client.put("/api/v1/data/123", new TestRequest("updated"));

        // Then
        assertThat(result).contains("true");
    }

    @Test
    @SuppressWarnings("unchecked")
    void deleteWithSuccessfulResponseShouldReturnBody() throws Exception {
        // Given
        when(ansHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(httpResponse);
        when(httpResponse.statusCode()).thenReturn(204);
        when(httpResponse.body()).thenReturn("");

        // When
        String result = client.delete("/api/v1/data/123");

        // Then
        assertThat(result).isEmpty();
    }

    @Test
    @SuppressWarnings("unchecked")
    void requestWithNetworkErrorShouldThrowAgentConnectionException() throws Exception {
        // Given
        when(ansHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenThrow(new IOException("Connection refused"));

        // When/Then
        assertThatThrownBy(() -> client.get("/api/v1/data"))
            .isInstanceOf(com.aliyun.ati.sdk.agent.exception.AgentConnectionException.class)
            .hasMessageContaining("Network error");
    }

    @Test
    @SuppressWarnings("unchecked")
    void getWith403ResponseShouldThrowAuthException() throws Exception {
        // Given
        HttpHeaders headers = mock(HttpHeaders.class);
        when(headers.firstValue("X-Request-Id")).thenReturn(java.util.Optional.empty());

        when(ansHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(httpResponse);
        when(httpResponse.statusCode()).thenReturn(403);
        when(httpResponse.body()).thenReturn("Forbidden");
        when(httpResponse.headers()).thenReturn(headers);

        // When/Then
        assertThatThrownBy(() -> client.get("/api/v1/data"))
            .isInstanceOf(ProtocolException.class)
            .hasMessageContaining("authorization");
    }

    @Test
    @SuppressWarnings("unchecked")
    void getWith500ResponseShouldThrowProtocolException() throws Exception {
        // Given
        HttpHeaders headers = mock(HttpHeaders.class);
        when(headers.firstValue("X-Request-Id")).thenReturn(java.util.Optional.empty());

        when(ansHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(httpResponse);
        when(httpResponse.statusCode()).thenReturn(500);
        when(httpResponse.body()).thenReturn("Internal Server Error");
        when(httpResponse.headers()).thenReturn(headers);

        // When/Then
        assertThatThrownBy(() -> client.get("/api/v1/data"))
            .isInstanceOf(ProtocolException.class)
            .hasMessageContaining("500");
    }

    @Test
    @SuppressWarnings("unchecked")
    void customRequestMethodShouldWork() throws Exception {
        // Given
        when(ansHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(httpResponse);
        when(httpResponse.statusCode()).thenReturn(200);
        when(httpResponse.body()).thenReturn("{\"result\":\"ok\"}");

        // When
        String result = client.request("PATCH", "/api/v1/data", "{\"field\":\"value\"}", null);

        // Then
        assertThat(result).contains("ok");
    }

    @Test
    @SuppressWarnings("unchecked")
    void customRequestWithHeadersShouldWork() throws Exception {
        // Given
        when(ansHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(httpResponse);
        when(httpResponse.statusCode()).thenReturn(200);
        when(httpResponse.body()).thenReturn("{}");

        java.util.Map<String, String> headers = java.util.Map.of("X-Custom", "value");

        // When
        String result = client.request("GET", "/api/v1/data", null, headers);

        // Then
        assertThat(result).isEqualTo("{}");
    }

    @Test
    @SuppressWarnings("unchecked")
    void postWithTypedResponseShouldDeserialize() throws Exception {
        // Given - response body is read as string first, then deserialized
        when(ansHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(httpResponse);
        when(httpResponse.statusCode()).thenReturn(201);
        when(httpResponse.body()).thenReturn("{\"value\":\"created\"}");

        // When
        TestResponse result = client.post("/api/v1/data", new TestRequest("test"), TestResponse.class);

        // Then
        assertThat(result.value).isEqualTo("created");
    }

    @Test
    @SuppressWarnings("unchecked")
    void putWithTypedResponseShouldDeserialize() throws Exception {
        // Given - response body is read as string first, then deserialized
        when(ansHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(httpResponse);
        when(httpResponse.statusCode()).thenReturn(200);
        when(httpResponse.body()).thenReturn("{\"value\":\"updated\"}");

        // When
        TestResponse result = client.put("/api/v1/data/123", new TestRequest("update"), TestResponse.class);

        // Then
        assertThat(result.value).isEqualTo("updated");
    }

    @Test
    @SuppressWarnings("unchecked")
    void deleteWithTypedResponseShouldDeserialize() throws Exception {
        // Given - response body is read as string first, then deserialized
        when(ansHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(httpResponse);
        when(httpResponse.statusCode()).thenReturn(200);
        when(httpResponse.body()).thenReturn("{\"value\":\"deleted\"}");

        // When
        TestResponse result = client.delete("/api/v1/data/123", TestResponse.class);

        // Then
        assertThat(result.value).isEqualTo("deleted");
    }

    @Test
    void pathWithoutLeadingSlashShouldBeNormalized() throws Exception {
        // Given
        when(ansHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(httpResponse);
        when(httpResponse.statusCode()).thenReturn(200);
        when(httpResponse.body()).thenReturn("{}");

        // When - path without leading slash
        String result = client.get("api/v1/data");

        // Then - should succeed without error
        assertThat(result).isEqualTo("{}");
    }

    @Test
    @SuppressWarnings("unchecked")
    void requestWithInterruptionShouldThrowAgentConnectionException() throws Exception {
        // Given
        when(ansHttpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenThrow(new InterruptedException("Thread interrupted"));

        // When/Then
        assertThatThrownBy(() -> client.get("/api/v1/data"))
            .isInstanceOf(com.aliyun.ati.sdk.agent.exception.AgentConnectionException.class)
            .hasMessageContaining("interrupted");
    }

    // Test helper classes
    private static class TestRequest {
        public String value;

        TestRequest(String value) {
            this.value = value;
        }
    }

    private static final class TestResponse {
        public String value;
    }
}
