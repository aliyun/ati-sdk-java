package com.aliyun.ati.sdk.agent.http;

import java.security.KeyStore;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

import com.aliyun.ati.sdk.exception.AtiException;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AtiVerifiedSslContextFactoryTest {

    private static X509TrustManager testTrustManager;

    @BeforeAll
    static void setUp() throws Exception {
        // Use a default trust manager for testing
        TrustManagerFactory tmf = TrustManagerFactory.getInstance(
            TrustManagerFactory.getDefaultAlgorithm());
        tmf.init((KeyStore) null);
        for (TrustManager tm : tmf.getTrustManagers()) {
            if (tm instanceof X509TrustManager) {
                testTrustManager = (X509TrustManager) tm;
                break;
            }
        }
    }

    @Test
    void shouldCreateSslContextWithNoMtls() {
        AtiVerifiedSslContextFactory.Result result =
            AtiVerifiedSslContextFactory.create(
                testTrustManager, null, null);

        assertThat(result).isNotNull();
        assertThat(result.getSslContext()).isNotNull();
        assertThat(result.getSslContext().getProtocol()).startsWith("TLS");
        assertThat(result.getTrustManager()).isNotNull();
        assertThat(result.getTrustManager())
            .isInstanceOf(CertificateCapturingTrustManager.class);
    }

    @Test
    void shouldThrowForNullTrustManager() {
        assertThatThrownBy(() ->
            AtiVerifiedSslContextFactory.create(null, null, null))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("idcaTrustManager");
    }

    @Test
    void shouldThrowWhenCertPathWithoutKeyPath() {
        assertThatThrownBy(() ->
            AtiVerifiedSslContextFactory.create(
                testTrustManager, "/some/cert.pem", null))
            .isInstanceOf(AtiException.class)
            .hasMessageContaining(
                "privateKeyPath is required when certificatePath is set");
    }

    @Test
    void shouldThrowWhenKeyPathWithoutCertPath() {
        assertThatThrownBy(() ->
            AtiVerifiedSslContextFactory.create(
                testTrustManager, null, "/some/key.pem"))
            .isInstanceOf(AtiException.class)
            .hasMessageContaining(
                "certificatePath is required when privateKeyPath is set");
    }

    @Test
    void shouldThrowForNonexistentCertFile() {
        assertThatThrownBy(() ->
            AtiVerifiedSslContextFactory.create(
                testTrustManager,
                "/nonexistent/cert.pem",
                "/nonexistent/key.pem"))
            .isInstanceOf(AtiException.class)
            .hasMessageContaining("Failed to create SSL context");
    }

    @Test
    void shouldThrowForMissingClasspathResource() {
        assertThatThrownBy(() ->
            AtiVerifiedSslContextFactory.create(
                testTrustManager,
                "classpath:nonexistent-cert.pem",
                "classpath:nonexistent-key.pem"))
            .isInstanceOf(AtiException.class)
            .hasMessageContaining("Resource not found on classpath");
    }

    @Test
    void shouldReturnInitializedSslContext() {
        AtiVerifiedSslContextFactory.Result result =
            AtiVerifiedSslContextFactory.create(
                testTrustManager, null, null);

        assertThat(result.getSslContext().getServerSessionContext())
            .isNotNull();
        assertThat(result.getSslContext().getClientSessionContext())
            .isNotNull();
    }
}
