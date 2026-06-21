package com.aliyun.ati.sdk.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Unit tests for AtiConfiguration.
 */
class AtiConfigurationTest {

    @Test
    @DisplayName("Should create configuration with OTE environment")
    void shouldCreateConfigWithOteEnvironment() {
        AtiConfiguration config = AtiConfiguration.builder()
            .environment(Environment.OTE)
            .build();

        assertThat(config.getBaseUrl()).isEqualTo("https://api.ote-ati.aliyun.com");
        assertThat(config.getEnvironment()).isEqualTo(Environment.OTE);
    }

    @Test
    @DisplayName("Should create configuration with PROD environment")
    void shouldCreateConfigWithProdEnvironment() {
        AtiConfiguration config = AtiConfiguration.builder()
            .environment(Environment.PROD)
            .build();

        assertThat(config.getBaseUrl()).isEqualTo("https://api.ati.aliyun.com");
        assertThat(config.getEnvironment()).isEqualTo(Environment.PROD);
    }

    @Test
    @DisplayName("Should override base URL when explicitly set")
    void shouldOverrideBaseUrl() {
        AtiConfiguration config = AtiConfiguration.builder()
            .environment(Environment.OTE)
            .baseUrl("http://localhost:8080")
            .build();

        assertThat(config.getBaseUrl()).isEqualTo("http://localhost:8080");
    }

    @Test
    @DisplayName("Should use default timeouts")
    void shouldUseDefaultTimeouts() {
        AtiConfiguration config = AtiConfiguration.builder()
            .environment(Environment.OTE)
            .build();

        assertThat(config.getConnectTimeout()).isEqualTo(Duration.ofSeconds(10));
        assertThat(config.getReadTimeout()).isEqualTo(Duration.ofSeconds(30));
    }

    @Test
    @DisplayName("Should set custom timeouts")
    void shouldSetCustomTimeouts() {
        AtiConfiguration config = AtiConfiguration.builder()
            .environment(Environment.OTE)
            .connectTimeout(Duration.ofSeconds(5))
            .readTimeout(Duration.ofSeconds(60))
            .build();

        assertThat(config.getConnectTimeout()).isEqualTo(Duration.ofSeconds(5));
        assertThat(config.getReadTimeout()).isEqualTo(Duration.ofSeconds(60));
    }

    @Test
    @DisplayName("Should configure retry settings")
    void shouldConfigureRetrySettings() {
        AtiConfiguration config = AtiConfiguration.builder()
            .environment(Environment.OTE)
            .enableRetry(5)
            .build();

        assertThat(config.isRetryEnabled()).isTrue();
        assertThat(config.getMaxRetries()).isEqualTo(5);
    }

    @Test
    @DisplayName("Should enable retry by default with 3 retries")
    void shouldEnableRetryByDefault() {
        AtiConfiguration config = AtiConfiguration.builder()
            .environment(Environment.OTE)
            .build();

        assertThat(config.isRetryEnabled()).isTrue();
        assertThat(config.getMaxRetries()).isEqualTo(3);
    }

    @Test
    @DisplayName("Should throw when environment is not set")
    void shouldThrowWhenEnvironmentNotSet() {
        assertThatThrownBy(() -> AtiConfiguration.builder()
            .build())
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("Environment is required");
    }

    @Test
    @DisplayName("Should allow custom base URL with explicit environment")
    void shouldAllowCustomBaseUrlWithExplicitEnvironment() {
        AtiConfiguration config = AtiConfiguration.builder()
            .environment(Environment.OTE)
            .baseUrl("http://custom-url.com")
            .build();

        assertThat(config.getBaseUrl()).isEqualTo("http://custom-url.com");
        assertThat(config.getEnvironment()).isEqualTo(Environment.OTE);
    }
}
