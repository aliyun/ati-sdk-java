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

    private volatile CrlCheckingTrustManager delegate;

    public TomcatDelegatingCrlTrustManager() throws Exception {
        if (IdcaCrlTrustManagerConfig.configCount() == 1) {
            this.delegate = buildDelegate(IdcaCrlTrustManagerConfig.requireSingleConfigured());
        }
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        delegateFor(chain).checkClientTrusted(chain, authType);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
            throws CertificateException {
        delegateFor(chain).checkClientTrusted(chain, authType, socket);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
            throws CertificateException {
        delegateFor(chain).checkClientTrusted(chain, authType, engine);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        serverDelegate().checkServerTrusted(chain, authType);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
            throws CertificateException {
        serverDelegate().checkServerTrusted(chain, authType, socket);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
            throws CertificateException {
        serverDelegate().checkServerTrusted(chain, authType, engine);
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        try {
            return serverDelegate().getAcceptedIssuers();
        } catch (CertificateException e) {
            return new X509Certificate[0];
        }
    }

    private CrlCheckingTrustManager delegateFor(X509Certificate[] chain) throws CertificateException {
        CrlCheckingTrustManager current = delegate;
        if (current != null) {
            return current;
        }
        synchronized (this) {
            if (delegate == null) {
                try {
                    IdcaCrlTrustManagerConfig.Config config = IdcaCrlTrustManagerConfig.resolveForChain(chain);
                    delegate = buildDelegate(config);
                } catch (CertificateException e) {
                    throw e;
                } catch (Exception e) {
                    throw new CertificateException("Failed to initialize IDCA CRL trust manager", e);
                }
            }
            return delegate;
        }
    }

    private CrlCheckingTrustManager serverDelegate() throws CertificateException {
        CrlCheckingTrustManager current = delegate;
        if (current != null) {
            return current;
        }
        if (IdcaCrlTrustManagerConfig.configCount() == 1) {
            synchronized (this) {
                if (delegate == null) {
                    try {
                        delegate = buildDelegate(IdcaCrlTrustManagerConfig.requireSingleConfigured());
                    } catch (Exception e) {
                        throw new CertificateException("Failed to initialize IDCA CRL trust manager", e);
                    }
                }
                return delegate;
            }
        }
        throw new CertificateException("Cannot resolve IDCA trust manager without a client certificate chain");
    }

    private static CrlCheckingTrustManager buildDelegate(IdcaCrlTrustManagerConfig.Config config)
            throws Exception {
        X509TrustManager idcaTrustManager = AtiIdcaCrlTomcatCustomizer.createTrustManager(config.trustStore());
        return new CrlCheckingTrustManager(idcaTrustManager, config.crlRevocationChecker());
    }
}
