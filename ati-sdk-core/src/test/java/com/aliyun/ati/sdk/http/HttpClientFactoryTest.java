package com.aliyun.ati.sdk.http;

import com.aliyun.ati.sdk.auth.AccessTokenCredentialsProvider;
import com.aliyun.ati.sdk.config.AtiConfiguration;
import com.aliyun.ati.sdk.config.Environment;
import org.junit.jupiter.api.Test;

import java.net.http.HttpClient;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

class HttpClientFactoryTest {

    @Test
    void shouldCreateClientWithConfiguration() {
        AtiConfiguration config = AtiConfiguration.builder()
            .environment(Environment.PRE)
            .credentialsProvider(new AccessTokenCredentialsProvider("token"))
            .connectTimeout(Duration.ofSeconds(5))
            .build();

        HttpClient client = HttpClientFactory.create(config);

        assertThat(client).isNotNull();
        assertThat(client.connectTimeout()).hasValue(Duration.ofSeconds(5));
        assertThat(client.followRedirects())
            .isEqualTo(HttpClient.Redirect.NORMAL);
        assertThat(client.version()).isEqualTo(HttpClient.Version.HTTP_1_1);
    }

    @Test
    void shouldCreateDefaultClient() {
        HttpClient client = HttpClientFactory.createDefault();

        assertThat(client).isNotNull();
        assertThat(client.connectTimeout()).hasValue(Duration.ofSeconds(10));
        assertThat(client.followRedirects())
            .isEqualTo(HttpClient.Redirect.NORMAL);
    }
}
