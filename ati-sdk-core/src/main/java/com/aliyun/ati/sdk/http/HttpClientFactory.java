package com.aliyun.ati.sdk.http;

import com.aliyun.ati.sdk.config.AtiConfiguration;

import java.net.http.HttpClient;
import java.time.Duration;

public final class HttpClientFactory {

    private HttpClientFactory() {
    }

    public static HttpClient create(AtiConfiguration config) {
        return HttpClient.newBuilder()
            .connectTimeout(config.getConnectTimeout())
            .followRedirects(HttpClient.Redirect.NORMAL)
            .version(HttpClient.Version.HTTP_1_1)
            .build();
    }

    public static HttpClient createDefault() {
        return HttpClient.newBuilder()
            .connectTimeout(Duration.ofSeconds(10))
            .followRedirects(HttpClient.Redirect.NORMAL)
            .version(HttpClient.Version.HTTP_1_1)
            .build();
    }
}
