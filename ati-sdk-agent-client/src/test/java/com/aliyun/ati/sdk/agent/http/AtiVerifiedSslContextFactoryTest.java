package com.aliyun.ati.sdk.agent.http;

import com.aliyun.ati.sdk.exception.AtiException;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AtiVerifiedSslContextFactoryTest {

    @Test
    void shouldCreateSslContextWithoutKeystore() {
        AtiVerifiedSslContextFactory.Result result =
            AtiVerifiedSslContextFactory.create();

        assertThat(result).isNotNull();
        assertThat(result.getSslContext()).isNotNull();
        assertThat(result.getSslContext().getProtocol()).startsWith("TLS");
        assertThat(result.getTrustManager()).isNotNull();
        assertThat(result.getTrustManager())
            .isInstanceOf(CertificateCapturingTrustManager.class);
    }

    @Test
    void shouldThrowForMissingKeystoreFile() {
        assertThatThrownBy(() ->
            AtiVerifiedSslContextFactory.create(
                "/nonexistent/keystore.p12", "password"))
            .isInstanceOf(AtiException.class)
            .hasMessageContaining("Failed to create SSL context");
    }

    @Test
    void shouldThrowForMissingClasspathKeystore() {
        assertThatThrownBy(() ->
            AtiVerifiedSslContextFactory.create(
                "classpath:nonexistent.p12", "password"))
            .isInstanceOf(AtiException.class)
            .hasMessageContaining("Keystore not found on classpath");
    }

    @Test
    void shouldCreateSslContextWithNullKeystoreArgs() {
        AtiVerifiedSslContextFactory.Result result =
            AtiVerifiedSslContextFactory.create(null, null);

        assertThat(result).isNotNull();
        assertThat(result.getSslContext()).isNotNull();
        assertThat(result.getTrustManager()).isNotNull();
    }

    @Test
    void shouldReturnInitializedSslContext() {
        AtiVerifiedSslContextFactory.Result result =
            AtiVerifiedSslContextFactory.create();

        assertThat(result.getSslContext().getServerSessionContext())
            .isNotNull();
        assertThat(result.getSslContext().getClientSessionContext())
            .isNotNull();
    }
}
