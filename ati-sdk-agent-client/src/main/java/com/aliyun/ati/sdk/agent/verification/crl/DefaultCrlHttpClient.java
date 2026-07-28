package com.aliyun.ati.sdk.agent.verification.crl;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.util.Objects;

/**
 * Default {@link CrlHttpClient} backed by {@link HttpClient}.
 */
public final class DefaultCrlHttpClient implements CrlHttpClient {

    private static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(30);

    private final HttpClient httpClient;
    private final Duration timeout;

    public DefaultCrlHttpClient() {
        this(HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NORMAL).build(), DEFAULT_TIMEOUT);
    }

    DefaultCrlHttpClient(HttpClient httpClient, Duration timeout) {
        this.httpClient = Objects.requireNonNull(httpClient, "httpClient");
        this.timeout = Objects.requireNonNull(timeout, "timeout");
    }

    @Override
    public byte[] fetch(URI uri) throws IOException {
        Objects.requireNonNull(uri, "uri");
        try {
            HttpRequest request = HttpRequest.newBuilder(uri)
                .timeout(timeout)
                .GET()
                .header("Accept", "application/pkix-crl")
                .build();
            HttpResponse<byte[]> response = httpClient.send(request, HttpResponse.BodyHandlers.ofByteArray());
            if (response.statusCode() < 200 || response.statusCode() >= 300) {
                throw new IOException("CRL fetch failed with HTTP " + response.statusCode() + " for " + uri);
            }
            return response.body();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new IOException("CRL fetch interrupted for " + uri, e);
        }
    }
}
