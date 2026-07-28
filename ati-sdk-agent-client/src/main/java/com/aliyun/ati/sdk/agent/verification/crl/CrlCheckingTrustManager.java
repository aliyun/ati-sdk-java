package com.aliyun.ati.sdk.agent.verification.crl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.X509ExtendedTrustManager;
import javax.net.ssl.X509TrustManager;
import java.net.Socket;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Objects;

/**
 * Server-side trust manager that performs IDCA PKI validation and CRL-based Certificate Revocation.
 *
 * <p>CRL checks run only for client (peer) certificates after the delegate trust manager accepts
 * the chain. Server certificate validation is delegated without CRL.</p>
 */
public final class CrlCheckingTrustManager extends X509ExtendedTrustManager {

    private static final Logger LOGGER = LoggerFactory.getLogger(CrlCheckingTrustManager.class);

    private final X509TrustManager delegate;
    private final CrlRevocationChecker crlRevocationChecker;

    public CrlCheckingTrustManager(X509TrustManager delegate, CrlRevocationChecker crlRevocationChecker) {
        this.delegate = Objects.requireNonNull(delegate, "delegate");
        this.crlRevocationChecker = Objects.requireNonNull(crlRevocationChecker, "crlRevocationChecker");
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        delegate.checkClientTrusted(chain, authType);
        enforceCrl(chain);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, Socket socket)
            throws CertificateException {
        if (delegate instanceof X509ExtendedTrustManager extended) {
            extended.checkClientTrusted(chain, authType, socket);
        } else {
            delegate.checkClientTrusted(chain, authType);
        }
        enforceCrl(chain);
    }

    @Override
    public void checkClientTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
            throws CertificateException {
        if (delegate instanceof X509ExtendedTrustManager extended) {
            extended.checkClientTrusted(chain, authType, engine);
        } else {
            delegate.checkClientTrusted(chain, authType);
        }
        enforceCrl(chain);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType) throws CertificateException {
        delegate.checkServerTrusted(chain, authType);
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, Socket socket)
            throws CertificateException {
        if (delegate instanceof X509ExtendedTrustManager extended) {
            extended.checkServerTrusted(chain, authType, socket);
        } else {
            delegate.checkServerTrusted(chain, authType);
        }
    }

    @Override
    public void checkServerTrusted(X509Certificate[] chain, String authType, SSLEngine engine)
            throws CertificateException {
        if (delegate instanceof X509ExtendedTrustManager extended) {
            extended.checkServerTrusted(chain, authType, engine);
        } else {
            delegate.checkServerTrusted(chain, authType);
        }
    }

    @Override
    public X509Certificate[] getAcceptedIssuers() {
        return delegate.getAcceptedIssuers();
    }

    private void enforceCrl(X509Certificate[] chain) throws CertificateException {
        if (chain == null || chain.length == 0) {
            return;
        }

        CrlRevocationResult result = crlRevocationChecker.check(chain[0], chain);
        if (result.isSkipped()) {
            LOGGER.debug("CRL check skipped for client certificate");
            return;
        }
        if (result.shouldRejectConnection()) {
            String message = result.message().orElse("CRL check failed");
            throw new CertificateException(message);
        }
    }
}
