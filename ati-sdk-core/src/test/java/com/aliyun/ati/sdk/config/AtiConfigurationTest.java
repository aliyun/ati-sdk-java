package com.aliyun.ati.sdk.config;

import com.aliyun.ati.sdk.auth.AccessTokenCredentialsProvider;
import com.aliyun.ati.sdk.auth.AtiCredentialsProvider;
import org.junit.jupiter.api.Test;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AtiConfigurationTest {

    private final AtiCredentialsProvider testProvider =
        new AccessTokenCredentialsProvider("test-token");

    @Test
    void shouldCreateConfigWithPreEnvironment() {
        AtiConfiguration config = AtiConfiguration.builder()
            .environment(Environment.PRE)
            .credentialsProvider(testProvider)
            .build();

        assertThat(config.getBaseUrl()).isEqualTo("https://ati-pre.aliyuncs.com");
        assertThat(config.getEnvironment()).isEqualTo(Environment.PRE);
    }

    @Test
    void shouldCreateConfigWithProdEnvironment() {
        AtiConfiguration config = AtiConfiguration.builder()
            .environment(Environment.PROD)
            .credentialsProvider(testProvider)
            .build();

        assertThat(config.getBaseUrl()).isEqualTo("https://ati.aliyuncs.com");
        assertThat(config.getEnvironment()).isEqualTo(Environment.PROD);
    }

    @Test
    void shouldOverrideBaseUrl() {
        AtiConfiguration config = AtiConfiguration.builder()
            .environment(Environment.PRE)
            .baseUrl("http://localhost:8080")
            .credentialsProvider(testProvider)
            .build();

        assertThat(config.getBaseUrl()).isEqualTo("http://localhost:8080");
    }

    @Test
    void shouldUseDefaultTimeouts() {
        AtiConfiguration config = AtiConfiguration.builder()
            .environment(Environment.PRE)
            .credentialsProvider(testProvider)
            .build();

        assertThat(config.getConnectTimeout()).isEqualTo(Duration.ofSeconds(10));
        assertThat(config.getReadTimeout()).isEqualTo(Duration.ofSeconds(30));
    }

    @Test
    void shouldSetCustomTimeouts() {
        AtiConfiguration config = AtiConfiguration.builder()
            .environment(Environment.PRE)
            .credentialsProvider(testProvider)
            .connectTimeout(Duration.ofSeconds(5))
            .readTimeout(Duration.ofSeconds(60))
            .build();

        assertThat(config.getConnectTimeout()).isEqualTo(Duration.ofSeconds(5));
        assertThat(config.getReadTimeout()).isEqualTo(Duration.ofSeconds(60));
    }

    @Test
    void shouldConfigureRetrySettings() {
        AtiConfiguration config = AtiConfiguration.builder()
            .environment(Environment.PRE)
            .credentialsProvider(testProvider)
            .maxRetries(5)
            .build();

        assertThat(config.isRetryEnabled()).isTrue();
        assertThat(config.getMaxRetries()).isEqualTo(5);
    }

    @Test
    void shouldEnableRetryByDefault() {
        AtiConfiguration config = AtiConfiguration.builder()
            .environment(Environment.PRE)
            .credentialsProvider(testProvider)
            .build();

        assertThat(config.isRetryEnabled()).isTrue();
        assertThat(config.getMaxRetries()).isEqualTo(3);
    }

    @Test
    void shouldDisableRetryWhenSetToZero() {
        AtiConfiguration config = AtiConfiguration.builder()
            .environment(Environment.PRE)
            .credentialsProvider(testProvider)
            .maxRetries(0)
            .build();

        assertThat(config.isRetryEnabled()).isFalse();
    }

    @Test
    void shouldThrowWhenCredentialsProviderIsNull() {
        assertThatThrownBy(() -> AtiConfiguration.builder()
            .environment(Environment.PRE)
            .build())
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("Credentials provider");
    }

    @Test
    void shouldThrowWhenEnvironmentNotSet() {
        assertThatThrownBy(() -> AtiConfiguration.builder()
            .credentialsProvider(testProvider)
            .build())
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("Environment is required");
    }

    @Test
    void shouldReturnCredentialsProvider() {
        AtiConfiguration config = AtiConfiguration.builder()
            .environment(Environment.PRE)
            .credentialsProvider(testProvider)
            .build();

        assertThat(config.getCredentialsProvider()).isSameAs(testProvider);
    }
}
