package com.aliyun.ati.sdk.agent.http;

import com.aliyun.ati.sdk.exception.AtiException;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AtiVerifiedSslContextFactoryTest {

    @Test
    void shouldCreateSslContextWithNoMtls() {
        AtiVerifiedSslContextFactory.Result result =
            AtiVerifiedSslContextFactory.create(null, null);

        assertThat(result).isNotNull();
        assertThat(result.getSslContext()).isNotNull();
        assertThat(result.getSslContext().getProtocol()).startsWith("TLS");
        assertThat(result.getTrustManager()).isNotNull();
        assertThat(result.getTrustManager())
            .isInstanceOf(CertificateCapturingTrustManager.class);
    }

    @Test
    void shouldThrowWhenCertPathWithoutKeyPath() {
        assertThatThrownBy(() ->
            AtiVerifiedSslContextFactory.create("/some/cert.pem", null))
            .isInstanceOf(AtiException.class)
            .hasMessageContaining(
                "privateKeyPath is required when certificatePath is set");
    }

    @Test
    void shouldThrowWhenKeyPathWithoutCertPath() {
        assertThatThrownBy(() ->
            AtiVerifiedSslContextFactory.create(null, "/some/key.pem"))
            .isInstanceOf(AtiException.class)
            .hasMessageContaining(
                "certificatePath is required when privateKeyPath is set");
    }

    @Test
    void shouldThrowForNonexistentCertFile() {
        assertThatThrownBy(() ->
            AtiVerifiedSslContextFactory.create(
                "/nonexistent/cert.pem",
                "/nonexistent/key.pem"))
            .isInstanceOf(AtiException.class)
            .hasMessageContaining("Failed to create SSL context");
    }

    @Test
    void shouldThrowForMissingClasspathResource() {
        assertThatThrownBy(() ->
            AtiVerifiedSslContextFactory.create(
                "classpath:nonexistent-cert.pem",
                "classpath:nonexistent-key.pem"))
            .isInstanceOf(AtiException.class)
            .hasMessageContaining("Resource not found on classpath");
    }

    @Test
    void shouldReturnInitializedSslContext() {
        AtiVerifiedSslContextFactory.Result result =
            AtiVerifiedSslContextFactory.create(null, null);

        assertThat(result.getSslContext().getServerSessionContext())
            .isNotNull();
        assertThat(result.getSslContext().getClientSessionContext())
            .isNotNull();
    }
}
