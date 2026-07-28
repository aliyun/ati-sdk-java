package com.aliyun.ati.sdk.spring;

import com.aliyun.ati.sdk.agent.verification.crl.CrlCheckingTrustManager;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

/**
 * Tomcat-instantiable trust manager that delegates to IDCA trust store validation and CRL checks.
 */
public final class TomcatDelegatingCrlTrustManager extends X509ExtendedTrustManager {

    private final CrlCheckingTrustManager delegate;

    public TomcatDelegatingCrlTrustManager() throws Exception {
        IdcaCrlTrustManagerConfig.Config config = IdcaCrlTrustManagerConfig.requireConfigured();
        X509TrustManager idcaTrustManager = AtiIdcaCrlTomcatCustomizer.createTrustManager(config.trustStore());
        this.delegate = new CrlCheckingTrustManager(idcaTrustManager, config.crlRevocationChecker());
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        delegate.checkClientTrusted(chain, authType);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
            throws CertificateException {
        delegate.checkClientTrusted(chain, authType, socket);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
            throws CertificateException {
        delegate.checkClientTrusted(chain, authType, engine);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        delegate.checkServerTrusted(chain, authType);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
            throws CertificateException {
        delegate.checkServerTrusted(chain, authType, socket);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
            throws CertificateException {
        delegate.checkServerTrusted(chain, authType, engine);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return delegate.getAcceptedIssuers();
    }
}
