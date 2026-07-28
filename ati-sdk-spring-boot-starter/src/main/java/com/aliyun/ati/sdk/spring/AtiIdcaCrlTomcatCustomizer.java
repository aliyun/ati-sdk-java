package com.aliyun.ati.sdk.spring;

import com.aliyun.ati.sdk.agent.verification.crl.CrlRevocationChecker;
import org.apache.catalina.connector.Connector;
import org.apache.coyote.http11.AbstractHttp11JsseProtocol;
import org.apache.tomcat.util.net.SSLHostConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.web.embedded.tomcat.TomcatConnectorCustomizer;

import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;
import java.io.IOException;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.util.Objects;

/**
 * Wires {@link TomcatDelegatingCrlTrustManager} into Tomcat after Spring Boot SSL setup.
 */
final class AtiIdcaCrlTomcatCustomizer implements TomcatConnectorCustomizer {

    private static final Logger LOG = LoggerFactory.getLogger(AtiIdcaCrlTomcatCustomizer.class);

    private final CrlRevocationChecker crlRevocationChecker;

    AtiIdcaCrlTomcatCustomizer(CrlRevocationChecker crlRevocationChecker) {
        this.crlRevocationChecker = Objects.requireNonNull(crlRevocationChecker, "crlRevocationChecker");
    }

    @Override
    public void customize(Connector connector) {
        if (!(connector.getProtocolHandler() instanceof AbstractHttp11JsseProtocol<?> protocol)) {
            LOG.debug("Skipping CRL wiring: connector protocol is not JSSE-based");
            return;
        }
        if (!protocol.isSSLEnabled()) {
            LOG.debug("Skipping CRL wiring: SSL is not enabled");
            return;
        }

        for (SSLHostConfig sslHostConfig : protocol.findSslHostConfigs()) {
            try {
                applyCrlTrustManager(sslHostConfig);
            } catch (GeneralSecurityException | IOException e) {
                throw new IllegalStateException("Failed to wire IDCA CRL trust manager", e);
            }
        }
    }

    private void applyCrlTrustManager(SSLHostConfig sslHostConfig)
            throws GeneralSecurityException, IOException {
        KeyStore trustStore = sslHostConfig.getTruststore();
        if (trustStore == null) {
            throw new IllegalStateException(
                "IDCA CRL checking is enabled but Tomcat SSL host '"
                    + sslHostConfig.getHostName()
                    + "' has no trust store; refusing fail-open mTLS");
        }

        IdcaCrlTrustManagerConfig.configure(
            sslHostConfig.getHostName(), trustStore, crlRevocationChecker);
        sslHostConfig.setTrustManagerClassName(TomcatDelegatingCrlTrustManager.class.getName());
        LOG.info("Installed CRL-checking trust manager for Tomcat SSL host {}", sslHostConfig.getHostName());
    }

    static X509TrustManager createTrustManager(KeyStore trustStore) throws GeneralSecurityException {
        TrustManagerFactory factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        factory.init(trustStore);
        for (TrustManager trustManager : factory.getTrustManagers()) {
            if (trustManager instanceof X509TrustManager x509TrustManager) {
                return x509TrustManager;
            }
        }
        throw new IllegalStateException("No X509TrustManager found in IDCA trust store");
    }
}
