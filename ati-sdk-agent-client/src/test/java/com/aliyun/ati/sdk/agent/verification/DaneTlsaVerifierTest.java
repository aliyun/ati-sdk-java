package com.aliyun.ati.sdk.agent.verification;

import java.security.cert.X509Certificate;
import java.time.Duration;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

class DaneTlsaVerifierTest {

    private DaneTlsaVerifier verifier;

    @BeforeEach
    void setUp() {
        verifier = new DaneTlsaVerifier(Duration.ofSeconds(3));
    }

    @Test
    void shouldRejectNullHost() {
        X509Certificate cert = mock(X509Certificate.class);

        assertThatThrownBy(() -> verifier.verify(null, 443, cert))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("host");
    }

    @Test
    void shouldRejectNullCert() {
        assertThatThrownBy(() -> verifier.verify("example.com", 443, null))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("serverCert");
    }

    @Test
    void shouldReturnNotFoundWhenNoTlsaRecord() {
        X509Certificate cert = mock(X509Certificate.class);

        VerificationResult result =
            verifier.verify("nonexistent.invalid", 443, cert);

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.getType())
            .isEqualTo(VerificationResult.Type.DANE);
        assertThat(result.getStatus())
            .isEqualTo(VerificationResult.Status.NOT_FOUND);
    }

    @Test
    void shouldRejectNullTimeout() {
        assertThatThrownBy(() -> new DaneTlsaVerifier(null))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("timeout");
    }

    @Test
    void shouldUseDefaultTimeout() {
        DaneTlsaVerifier defaultVerifier = new DaneTlsaVerifier();
        X509Certificate cert = mock(X509Certificate.class);

        VerificationResult result =
            defaultVerifier.verify("nonexistent.invalid", 443, cert);

        assertThat(result.getType())
            .isEqualTo(VerificationResult.Type.DANE);
    }
}
