package com.aliyun.ati.sdk.agent.http;

import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import javax.security.auth.x500.X500Principal;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class CertificateCapturingTrustManagerTest {

    private X509TrustManager mockDelegate;
    private X509ExtendedTrustManager mockExtendedDelegate;
    private X509Certificate mockCert;
    private X509Certificate[] certChain;

    @BeforeEach
    void setUp() {
        mockDelegate = mock(X509TrustManager.class);
        mockExtendedDelegate = mock(X509ExtendedTrustManager.class);
        mockCert = mock(X509Certificate.class);
        when(mockCert.getSubjectX500Principal())
            .thenReturn(new X500Principal("CN=test.example.com"));
        certChain = new X509Certificate[]{mockCert};
    }

    @Test
    void shouldRejectNullDelegate() {
        assertThatThrownBy(() -> new CertificateCapturingTrustManager(null))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("delegate");
    }

    @Test
    void shouldDelegateCheckServerTrusted() throws CertificateException {
        CertificateCapturingTrustManager tm =
            new CertificateCapturingTrustManager(mockDelegate);

        tm.checkServerTrusted(certChain, "RSA");

        verify(mockDelegate).checkServerTrusted(certChain, "RSA");
    }

    @Test
    void shouldCaptureCertChain() throws CertificateException {
        CertificateCapturingTrustManager tm =
            new CertificateCapturingTrustManager(mockDelegate);

        tm.checkServerTrusted(certChain, "RSA");

        String key = mockCert.getSubjectX500Principal().getName();
        X509Certificate[] captured = tm.getCapturedCerts(key);
        assertThat(captured).isNotNull();
        assertThat(captured).hasSize(1);
        assertThat(captured[0]).isSameAs(mockCert);
    }

    @Test
    void shouldCloneCapturedCerts() throws CertificateException {
        CertificateCapturingTrustManager tm =
            new CertificateCapturingTrustManager(mockDelegate);

        tm.checkServerTrusted(certChain, "RSA");

        String key = mockCert.getSubjectX500Principal().getName();
        X509Certificate[] first = tm.getCapturedCerts(key);
        X509Certificate[] second = tm.getCapturedCerts(key);
        assertThat(first).isNotNull();
        assertThat(second).isNotNull();
        assertThat(first).isNotSameAs(second);
    }

    @Test
    void shouldReturnNullForUncapturedKey() {
        CertificateCapturingTrustManager tm =
            new CertificateCapturingTrustManager(mockDelegate);

        assertThat(tm.getCapturedCerts("CN=unknown.example.com")).isNull();
    }

    @Test
    void shouldReturnLastCapturedServerCert() throws CertificateException {
        CertificateCapturingTrustManager tm =
            new CertificateCapturingTrustManager(mockDelegate);

        tm.checkServerTrusted(certChain, "RSA");

        X509Certificate lastCert = tm.getLastCapturedServerCert();
        assertThat(lastCert).isSameAs(mockCert);
    }

    @Test
    void shouldReturnNullWhenNothingCaptured() {
        CertificateCapturingTrustManager tm =
            new CertificateCapturingTrustManager(mockDelegate);

        assertThat(tm.getLastCapturedServerCert()).isNull();
    }

    @Test
    void shouldDelegateCheckClientTrusted() throws CertificateException {
        CertificateCapturingTrustManager tm =
            new CertificateCapturingTrustManager(mockDelegate);

        tm.checkClientTrusted(certChain, "RSA");

        verify(mockDelegate).checkClientTrusted(certChain, "RSA");
    }

    @Test
    void shouldDelegateGetAcceptedIssuers() {
        X509Certificate[] issuers = new X509Certificate[]{mockCert};
        when(mockDelegate.getAcceptedIssuers()).thenReturn(issuers);
        CertificateCapturingTrustManager tm =
            new CertificateCapturingTrustManager(mockDelegate);

        X509Certificate[] result = tm.getAcceptedIssuers();

        assertThat(result).isSameAs(issuers);
        verify(mockDelegate).getAcceptedIssuers();
    }

    @Test
    void shouldCaptureCertsWithEngine() throws CertificateException {
        CertificateCapturingTrustManager tm =
            new CertificateCapturingTrustManager(mockExtendedDelegate);
        SSLEngine engine = mock(SSLEngine.class);
        when(engine.getPeerHost()).thenReturn("secure.example.com");

        tm.checkServerTrusted(certChain, "RSA", engine);

        verify(mockExtendedDelegate)
            .checkServerTrusted(certChain, "RSA", engine);
        X509Certificate[] captured =
            tm.getCapturedCerts("secure.example.com");
        assertThat(captured).isNotNull();
        assertThat(captured).hasSize(1);
    }

    @Test
    void shouldCaptureCertsWithSocket() throws CertificateException {
        CertificateCapturingTrustManager tm =
            new CertificateCapturingTrustManager(mockExtendedDelegate);
        Socket socket = mock(Socket.class);
        when(socket.getRemoteSocketAddress())
            .thenReturn(new InetSocketAddress("socket.example.com", 443));

        tm.checkServerTrusted(certChain, "RSA", socket);

        verify(mockExtendedDelegate)
            .checkServerTrusted(certChain, "RSA", socket);
        X509Certificate[] captured =
            tm.getCapturedCerts("socket.example.com");
        assertThat(captured).isNotNull();
    }

    @Test
    void shouldFallbackToBasicDelegateForSocket() throws CertificateException {
        CertificateCapturingTrustManager tm =
            new CertificateCapturingTrustManager(mockDelegate);
        Socket socket = mock(Socket.class);
        when(socket.getRemoteSocketAddress())
            .thenReturn(new InetSocketAddress("basic.example.com", 443));

        tm.checkServerTrusted(certChain, "RSA", socket);

        verify(mockDelegate).checkServerTrusted(certChain, "RSA");
    }

    @Test
    void shouldFallbackToBasicDelegateForEngine() throws CertificateException {
        CertificateCapturingTrustManager tm =
            new CertificateCapturingTrustManager(mockDelegate);
        SSLEngine engine = mock(SSLEngine.class);
        when(engine.getPeerHost()).thenReturn("basic.example.com");

        tm.checkServerTrusted(certChain, "RSA", engine);

        verify(mockDelegate).checkServerTrusted(certChain, "RSA");
    }

    @Test
    void shouldDelegateClientTrustedWithSocket() throws CertificateException {
        CertificateCapturingTrustManager tm =
            new CertificateCapturingTrustManager(mockExtendedDelegate);
        Socket socket = mock(Socket.class);

        tm.checkClientTrusted(certChain, "RSA", socket);

        verify(mockExtendedDelegate)
            .checkClientTrusted(certChain, "RSA", socket);
    }

    @Test
    void shouldDelegateClientTrustedWithEngine() throws CertificateException {
        CertificateCapturingTrustManager tm =
            new CertificateCapturingTrustManager(mockExtendedDelegate);
        SSLEngine engine = mock(SSLEngine.class);

        tm.checkClientTrusted(certChain, "RSA", engine);

        verify(mockExtendedDelegate)
            .checkClientTrusted(certChain, "RSA", engine);
    }

    @Test
    void shouldPropagateExceptionFromDelegate() throws CertificateException {
        CertificateCapturingTrustManager tm =
            new CertificateCapturingTrustManager(mockExtendedDelegate);
        SSLEngine engine = mock(SSLEngine.class);
        when(engine.getPeerHost()).thenReturn("fail.example.com");

        doThrow(new CertificateException("Untrusted"))
            .when(mockExtendedDelegate)
            .checkServerTrusted(any(), eq("RSA"), eq(engine));

        assertThatThrownBy(
            () -> tm.checkServerTrusted(certChain, "RSA", engine))
            .isInstanceOf(CertificateException.class)
            .hasMessage("Untrusted");
    }

    @Test
    void shouldNotCaptureNullChain() throws CertificateException {
        CertificateCapturingTrustManager tm =
            new CertificateCapturingTrustManager(mockDelegate);

        tm.checkServerTrusted(null, "RSA");

        assertThat(tm.getLastCapturedServerCert()).isNull();
    }

    @Test
    void shouldNotCaptureEmptyChain() throws CertificateException {
        CertificateCapturingTrustManager tm =
            new CertificateCapturingTrustManager(mockDelegate);

        tm.checkServerTrusted(new X509Certificate[0], "RSA");

        assertThat(tm.getLastCapturedServerCert()).isNull();
    }

    @Test
    void shouldFallbackToSubjectWhenEngineHostnameIsNull()
            throws CertificateException {
        CertificateCapturingTrustManager tm =
            new CertificateCapturingTrustManager(mockExtendedDelegate);
        SSLEngine engine = mock(SSLEngine.class);
        when(engine.getPeerHost()).thenReturn(null);

        tm.checkServerTrusted(certChain, "RSA", engine);

        // Should fall back to subject-based key
        String key = mockCert.getSubjectX500Principal().getName();
        assertThat(tm.getCapturedCerts(key)).isNotNull();
    }

    @Test
    void shouldFallbackToSubjectWhenSocketAddressIsNull()
            throws CertificateException {
        CertificateCapturingTrustManager tm =
            new CertificateCapturingTrustManager(mockExtendedDelegate);
        Socket socket = mock(Socket.class);
        when(socket.getRemoteSocketAddress()).thenReturn(null);

        tm.checkServerTrusted(certChain, "RSA", socket);

        // Should fall back to subject-based key
        String key = mockCert.getSubjectX500Principal().getName();
        assertThat(tm.getCapturedCerts(key)).isNotNull();
    }
}
