package com.aliyun.ati.sdk.transparency;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.Objects;

import com.aliyun.ati.sdk.exception.AtiException;
import com.aliyun.ati.sdk.transparency.model.TransparencyLogResponse;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * HTTP client for the ATI Transparency Log API.
 *
 * <p>Provides methods to query transparency log entries for agents
 * and to retrieve root public keys used for seal verification.
 */
public final class AtiTransparencyClient {

    private static final Logger LOG = LoggerFactory.getLogger(AtiTransparencyClient.class);

    private final String baseUrl;
    private final HttpClient httpClient;
    private final ObjectMapper objectMapper;

    /**
     * Creates a new transparency client.
     *
     * @param baseUrl    the base URL of the TL API (e.g. {@code https://tl.ansagent.cn:8180})
     * @param httpClient the JDK HTTP client to use for requests
     */
    public AtiTransparencyClient(String baseUrl, HttpClient httpClient) {
        this.baseUrl = Objects.requireNonNull(baseUrl, "baseUrl must not be null");
        this.httpClient = Objects.requireNonNull(httpClient, "httpClient must not be null");
        this.objectMapper = new ObjectMapper();
    }

    /**
     * Fetches the latest transparency log entry for the given agent.
     *
     * @param agentId the agent identifier
     * @return the deserialized transparency log response
     * @throws AtiException if the agent is not found (404), the API returns an error,
     *                      or the response cannot be parsed
     */
    public TransparencyLogResponse getLatestLog(String agentId) {
        Objects.requireNonNull(agentId, "agentId must not be null");
        String url = baseUrl + "/tl/agents/" + agentId + "/logs/latest";
        LOG.debug("Querying TL for agent: {}", agentId);

        HttpResponse<String> response = sendGet(url);

        if (response.statusCode() == 404) {
            throw new AtiException("Agent not found: " + agentId);
        }
        if (response.statusCode() != 200) {
            throw new AtiException("TL API error: " + response.statusCode());
        }

        try {
            return objectMapper.readValue(response.body(), TransparencyLogResponse.class);
        } catch (Exception e) {
            throw new AtiException("Failed to parse TL response for agent: " + agentId, e);
        }
    }

    /**
     * Fetches the TL root public keys used for seal verification.
     *
     * @return the raw response body containing the root keys (typically PEM-encoded)
     * @throws AtiException if the API returns an error
     */
    public String getRootKeys() {
        String url = baseUrl + "/tl/root-keys";
        LOG.debug("Fetching TL root keys");

        HttpResponse<String> response = sendGet(url);

        if (response.statusCode() != 200) {
            throw new AtiException("TL API error: " + response.statusCode());
        }
        return response.body();
    }

    private HttpResponse<String> sendGet(String url) {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(url))
                .header("Accept", "application/json")
                .GET()
                .build();
            return httpClient.send(request, HttpResponse.BodyHandlers.ofString());
        } catch (IOException e) {
            throw new AtiException("HTTP request failed: " + url, e);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new AtiException("HTTP request interrupted: " + url, e);
        }
    }
}
