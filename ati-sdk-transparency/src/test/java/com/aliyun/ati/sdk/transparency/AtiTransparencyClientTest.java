package com.aliyun.ati.sdk.transparency;

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;

import com.aliyun.ati.sdk.exception.AtiException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AtiTransparencyClientTest {

    private HttpClient httpClient;
    private AtiTransparencyClient client;

    @BeforeEach
    void setUp() {
        httpClient = mock(HttpClient.class);
        client = new AtiTransparencyClient("https://tl.ansagent.cn:8180", httpClient);
    }

    @Test
    void shouldGetLatestLog() throws Exception {
        String json = """
            {
                "status": "ACTIVE",
                "schemaVersion": "ATI-TL-V1",
                "payload": {
                    "agentId": "test-agent-id",
                    "certificates": {
                        "serverCertFingerprint": "SHA-256:abc123"
                    }
                }
            }
            """;
        mockResponse(200, json);

        var response = client.getLatestLog("test-agent-id");

        assertThat(response.getStatus()).isEqualTo("ACTIVE");
        assertThat(response.getPayload().getAgentId()).isEqualTo("test-agent-id");
    }

    @Test
    void shouldThrowOnAgentNotFound() throws Exception {
        mockResponse(404, "");

        assertThatThrownBy(() -> client.getLatestLog("unknown"))
            .isInstanceOf(AtiException.class)
            .hasMessageContaining("Agent not found");
    }

    @Test
    void shouldThrowOnServerError() throws Exception {
        mockResponse(500, "");

        assertThatThrownBy(() -> client.getLatestLog("test"))
            .isInstanceOf(AtiException.class)
            .hasMessageContaining("500");
    }

    @Test
    void shouldGetRootKeys() throws Exception {
        String pem = "-----BEGIN PUBLIC KEY-----\nMFkwEwYH...\n-----END PUBLIC KEY-----";
        mockResponse(200, pem);

        String result = client.getRootKeys();

        assertThat(result).contains("BEGIN PUBLIC KEY");
    }

    @Test
    void shouldThrowOnRootKeysError() throws Exception {
        mockResponse(503, "");

        assertThatThrownBy(() -> client.getRootKeys())
            .isInstanceOf(AtiException.class)
            .hasMessageContaining("503");
    }

    @SuppressWarnings("unchecked")
    private void mockResponse(int statusCode, String body) throws Exception {
        HttpResponse<String> response = mock(HttpResponse.class);
        when(response.statusCode()).thenReturn(statusCode);
        when(response.body()).thenReturn(body);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
            .thenReturn(response);
    }
}
