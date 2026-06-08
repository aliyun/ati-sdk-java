package com.aliyun.ati.sdk.agent;

import java.net.http.HttpClient;
import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

import com.aliyun.ati.sdk.agent.http.CertificateCapturingTrustManager;
import com.aliyun.ati.sdk.agent.verification.DefaultConnectionVerifier;
import com.aliyun.ati.sdk.agent.verification.PreVerificationResult;
import com.aliyun.ati.sdk.agent.verification.VerificationResult;
import com.aliyun.ati.sdk.discovery.AtiAgentDescriptor;
import com.aliyun.ati.sdk.exception.AtiException;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class AtiConnectionTest {

    private HttpClient httpClient;
    private AtiAgentDescriptor descriptor;
    private PreVerificationResult preResult;
    private DefaultConnectionVerifier connectionVerifier;
    private CertificateCapturingTrustManager trustManager;

    @BeforeEach
    void setUp() {
        httpClient = mock(HttpClient.class);
        descriptor = new AtiAgentDescriptor(
            "example.com", "v1", null, "agent-001");
        preResult = new PreVerificationResult(
            descriptor, VerificationPolicy.GOLD,
            Collections.emptyList(), null);
        connectionVerifier = mock(DefaultConnectionVerifier.class);
        trustManager = mock(CertificateCapturingTrustManager.class);
    }

    @Test
    void shouldCreateConnection() {
        AtiConnection conn = new AtiConnection(
            httpClient, descriptor, preResult,
            connectionVerifier, trustManager);

        assertThat(conn.getHttpClient()).isSameAs(httpClient);
        assertThat(conn.getDescriptor()).isSameAs(descriptor);
    }

    @Test
    void shouldThrowWhenNoCertCapturedOnVerify() {
        when(trustManager.getLastCapturedServerCert())
            .thenReturn(null);

        AtiConnection conn = new AtiConnection(
            httpClient, descriptor, preResult,
            connectionVerifier, trustManager);

        assertThatThrownBy(conn::verify)
            .isInstanceOf(AtiException.class)
            .hasMessageContaining("No server certificate captured");
    }

    @Test
    void shouldDelegateVerifyToPostVerify() {
        X509Certificate serverCert = mock(X509Certificate.class);
        when(trustManager.getLastCapturedServerCert())
            .thenReturn(serverCert);

        List<VerificationResult> expected = List.of(
            VerificationResult.success(VerificationResult.Type.DANE));
        when(connectionVerifier.postVerify(
                any(X509Certificate.class),
                any(PreVerificationResult.class)))
            .thenReturn(expected);

        AtiConnection conn = new AtiConnection(
            httpClient, descriptor, preResult,
            connectionVerifier, trustManager);

        List<VerificationResult> results = conn.verify();

        assertThat(results).isSameAs(expected);
    }

    @Test
    void shouldRejectNullHttpClient() {
        assertThatThrownBy(() -> new AtiConnection(
                null, descriptor, preResult,
                connectionVerifier, trustManager))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("httpClient");
    }

    @Test
    void shouldRejectNullDescriptor() {
        assertThatThrownBy(() -> new AtiConnection(
                httpClient, null, preResult,
                connectionVerifier, trustManager))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("descriptor");
    }

    @Test
    void shouldRejectNullPreResult() {
        assertThatThrownBy(() -> new AtiConnection(
                httpClient, descriptor, null,
                connectionVerifier, trustManager))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("preResult");
    }

    @Test
    void shouldRejectNullConnectionVerifier() {
        assertThatThrownBy(() -> new AtiConnection(
                httpClient, descriptor, preResult,
                null, trustManager))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("connectionVerifier");
    }

    @Test
    void shouldRejectNullTrustManager() {
        assertThatThrownBy(() -> new AtiConnection(
                httpClient, descriptor, preResult,
                connectionVerifier, null))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("trustManager");
    }
}
