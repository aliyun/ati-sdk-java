package com.aliyun.ati.sdk.http;

import com.aliyun.ati.sdk.config.AtiConfiguration;
import com.aliyun.ati.sdk.config.Environment;
import org.junit.jupiter.api.Test;

import java.net.http.HttpClient;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for HttpClientFactory.
 */
class HttpClientFactoryTest {

    @Test
    void createWithConfigurationShouldReturnConfiguredClient() {
        AtiConfiguration config = AtiConfiguration.builder()
            .environment(Environment.OTE)
            .connectTimeout(Duration.ofSeconds(30))
            .build();

        HttpClient client = HttpClientFactory.create(config);

        assertThat(client).isNotNull();
        assertThat(client.connectTimeout()).isPresent();
        assertThat(client.connectTimeout().get()).isEqualTo(Duration.ofSeconds(30));
    }

    @Test
    void createDefaultShouldReturnClientWithDefaults() {
        HttpClient client = HttpClientFactory.createDefault();

        assertThat(client).isNotNull();
        assertThat(client.connectTimeout()).isPresent();
        assertThat(client.connectTimeout().get()).isEqualTo(Duration.ofSeconds(10));
    }

    @Test
    void createShouldConfigureRedirectPolicy() {
        AtiConfiguration config = AtiConfiguration.builder()
            .environment(Environment.OTE)
            .build();

        HttpClient client = HttpClientFactory.create(config);

        assertThat(client.followRedirects()).isEqualTo(HttpClient.Redirect.NORMAL);
    }

    @Test
    void createDefaultShouldConfigureRedirectPolicy() {
        HttpClient client = HttpClientFactory.createDefault();

        assertThat(client.followRedirects()).isEqualTo(HttpClient.Redirect.NORMAL);
    }
}
