package com.aliyun.ati.sdk.http;

import com.aliyun.ati.sdk.config.AtiConfiguration;

import java.net.http.HttpClient;
import java.time.Duration;

/**
 * Factory for creating configured HTTP clients.
 *
 * <p>This factory creates {@link HttpClient} instances configured according
 * to the provided {@link AtiConfiguration}.</p>
 */
public final class HttpClientFactory {

    private HttpClientFactory() {
        // Utility class
    }

    /**
     * Creates a new HTTP client configured according to the provided configuration.
     *
     * @param config the SDK configuration
     * @return a configured HTTP client
     */
    public static HttpClient create(AtiConfiguration config) {
        return HttpClient.newBuilder()
            .connectTimeout(config.getConnectTimeout())
            .followRedirects(HttpClient.Redirect.NORMAL)
            .version(HttpClient.Version.HTTP_1_1)
            .build();
    }

    /**
     * Creates a new HTTP client with default configuration.
     *
     * @return a default HTTP client
     */
    public static HttpClient createDefault() {
        return HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .followRedirects(HttpClient.Redirect.NORMAL)
            .version(HttpClient.Version.HTTP_1_1)
            .build();
    }
}