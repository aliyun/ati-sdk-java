package com.aliyun.ati.sdk.auth;

import com.aliyun.ati.sdk.exception.AtiAuthenticationException;
import org.junit.jupiter.api.Test;

import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class RefreshableTokenCredentialsProviderTest {

    @Test
    void shouldCallSupplierOnEachResolve() {
        AtomicInteger counter = new AtomicInteger(0);
        RefreshableTokenCredentialsProvider provider =
            new RefreshableTokenCredentialsProvider(
                () -> "token-" + counter.incrementAndGet());

        AtiCredentials first = provider.resolveCredentials();
        AtiCredentials second = provider.resolveCredentials();

        assertThat(first.getAccessToken()).isEqualTo("token-1");
        assertThat(second.getAccessToken()).isEqualTo("token-2");
    }

    @Test
    void shouldThrowWhenSupplierReturnsNull() {
        RefreshableTokenCredentialsProvider provider =
            new RefreshableTokenCredentialsProvider(() -> null);

        assertThatThrownBy(provider::resolveCredentials)
            .isInstanceOf(AtiAuthenticationException.class)
            .hasMessageContaining("null or blank");
    }

    @Test
    void shouldThrowWhenSupplierReturnsBlank() {
        RefreshableTokenCredentialsProvider provider =
            new RefreshableTokenCredentialsProvider(() -> "  ");

        assertThatThrownBy(provider::resolveCredentials)
            .isInstanceOf(AtiAuthenticationException.class)
            .hasMessageContaining("null or blank");
    }

    @Test
    void shouldWrapSupplierException() {
        RefreshableTokenCredentialsProvider provider =
            new RefreshableTokenCredentialsProvider(() -> {
                throw new RuntimeException("network error");
            });

        assertThatThrownBy(provider::resolveCredentials)
            .isInstanceOf(AtiAuthenticationException.class)
            .hasMessageContaining("Failed to obtain access token")
            .hasCauseInstanceOf(RuntimeException.class);
    }

    @Test
    void shouldRejectNullSupplier() {
        assertThatThrownBy(() -> new RefreshableTokenCredentialsProvider(null))
            .isInstanceOf(IllegalArgumentException.class);
    }
}
