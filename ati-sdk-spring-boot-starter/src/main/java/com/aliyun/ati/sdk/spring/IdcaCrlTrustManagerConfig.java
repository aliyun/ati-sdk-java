package com.aliyun.ati.sdk.spring;

import com.aliyun.ati.sdk.agent.verification.crl.CrlRevocationChecker;

import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Thread-safe holder for wiring {@link TomcatDelegatingCrlTrustManager} via Tomcat's
 * {@code trustManagerClassName} hook.
 *
 * <p>Configs are keyed by Tomcat SSL host name so multiple {@code SSLHostConfig} entries
 * do not overwrite each other. When only one host is registered, {@link TomcatDelegatingCrlTrustManager}
 * can initialize eagerly; otherwise the matching trust store is resolved from the presented chain.</p>
 */
final class IdcaCrlTrustManagerConfig {

    private static final ConcurrentHashMap<String, Config> CONFIGS = new ConcurrentHashMap<>();

    private IdcaCrlTrustManagerConfig() {
    }

    static void configure(String hostName, KeyStore trustStore, CrlRevocationChecker crlRevocationChecker) {
        Objects.requireNonNull(hostName, "hostName");
        CONFIGS.put(hostName, new Config(
            Objects.requireNonNull(trustStore, "trustStore"),
            Objects.requireNonNull(crlRevocationChecker, "crlRevocationChecker")
        ));
    }

    static Config requireSingleConfigured() {
        if (CONFIGS.size() != 1) {
            throw new IllegalStateException(
                "Expected exactly one IDCA CRL trust manager config, found " + CONFIGS.size());
        }
        return CONFIGS.values().iterator().next();
    }

    static int configCount() {
        return CONFIGS.size();
    }

    static Config resolveForChain(X509Certificate[] chain) throws CertificateException {
        if (chain == null || chain.length == 0) {
            throw new CertificateException("Client certificate chain is empty");
        }
        if (CONFIGS.size() == 1) {
            return CONFIGS.values().iterator().next();
        }
        CertificateException lastFailure = null;
        for (Config config : CONFIGS.values()) {
            try {
                AtiIdcaCrlTomcatCustomizer.createTrustManager(config.trustStore())
                    .checkClientTrusted(chain, "EC");
                return config;
            } catch (CertificateException e) {
                lastFailure = e;
            } catch (GeneralSecurityException e) {
                lastFailure = new CertificateException("Failed to validate chain against IDCA trust store", e);
            }
        }
        throw lastFailure != null
            ? lastFailure
            : new CertificateException("No IDCA trust store accepts client certificate chain");
    }

    static void clear() {
        CONFIGS.clear();
    }

    record Config(KeyStore trustStore, CrlRevocationChecker crlRevocationChecker) {
    }
}
