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
    void shouldCreateSslContextWithIdcaTrustManager() {
        AtiVerifiedSslContextFactory.Result result =
            AtiVerifiedSslContextFactory.create(testTrustManager, null, null);

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
    void shouldThrowForMissingKeystoreFile() {
        assertThatThrownBy(() ->
            AtiVerifiedSslContextFactory.create(
                testTrustManager, "/nonexistent/keystore.p12", "password"))
            .isInstanceOf(AtiException.class)
            .hasMessageContaining("Failed to create SSL context");
    }

    @Test
    void shouldThrowForMissingClasspathKeystore() {
        assertThatThrownBy(() ->
            AtiVerifiedSslContextFactory.create(
                testTrustManager, "classpath:nonexistent.p12", "password"))
            .isInstanceOf(AtiException.class)
            .hasMessageContaining("Keystore not found on classpath");
    }

    @Test
    void shouldReturnInitializedSslContext() {
        AtiVerifiedSslContextFactory.Result result =
            AtiVerifiedSslContextFactory.create(testTrustManager, null, null);

        assertThat(result.getSslContext().getServerSessionContext()).isNotNull();
        assertThat(result.getSslContext().getClientSessionContext()).isNotNull();
    }
}
