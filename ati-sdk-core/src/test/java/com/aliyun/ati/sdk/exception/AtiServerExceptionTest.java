package com.aliyun.ati.sdk.exception;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AtiServerExceptionTest {

    @Test
    void shouldStoreStatusCode() {
        AtiServerException ex = new AtiServerException("error", 503);
        assertThat(ex.getStatusCode()).isEqualTo(503);
        assertThat(ex.getMessage()).isEqualTo("error");
    }

    @Test
    void shouldDefaultTo500() {
        AtiServerException ex = new AtiServerException("error");
        assertThat(ex.getStatusCode()).isEqualTo(500);
    }

    @Test
    void shouldBeRetryableFor5xx() {
        assertThat(new AtiServerException("err", 500).isRetryable()).isTrue();
        assertThat(new AtiServerException("err", 502).isRetryable()).isTrue();
        assertThat(new AtiServerException("err", 503).isRetryable()).isTrue();
        assertThat(new AtiServerException("err", 599).isRetryable()).isTrue();
    }

    @Test
    void shouldNotBeRetryableForNon5xx() {
        assertThat(new AtiServerException("err", 400).isRetryable()).isFalse();
        assertThat(new AtiServerException("err", 404).isRetryable()).isFalse();
        assertThat(new AtiServerException("err", 499).isRetryable()).isFalse();
    }

    @Test
    void shouldStoreRequestId() {
        AtiServerException ex = new AtiServerException("error", 500, "req-123");
        assertThat(ex.getRequestId()).isEqualTo("req-123");
    }

    @Test
    void shouldStoreCauseAndRequestId() {
        RuntimeException cause = new RuntimeException("root");
        AtiServerException ex = new AtiServerException("error", 500, cause, "req-456");
        assertThat(ex.getCause()).isSameAs(cause);
        assertThat(ex.getRequestId()).isEqualTo("req-456");
    }
}
