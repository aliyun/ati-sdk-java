package com.aliyun.ati.sdk.spring;

import com.aliyun.ati.sdk.agent.verification.crl.CrlRevocationChecker;

import java.security.KeyStore;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Thread-safe holder for wiring {@link TomcatDelegatingCrlTrustManager} via Tomcat's
 * {@code trustManagerClassName} hook.
 */
final class IdcaCrlTrustManagerConfig {

    private static final AtomicReference<Config> CONFIG = new AtomicReference<>();

    private IdcaCrlTrustManagerConfig() {
    }

    static void configure(KeyStore trustStore, CrlRevocationChecker crlRevocationChecker) {
        CONFIG.set(new Config(
            Objects.requireNonNull(trustStore, "trustStore"),
            Objects.requireNonNull(crlRevocationChecker, "crlRevocationChecker")
        ));
    }

    static Config requireConfigured() {
        Config config = CONFIG.get();
        if (config == null) {
            throw new IllegalStateException("IDCA CRL trust manager is not configured");
        }
        return config;
    }

    record Config(KeyStore trustStore, CrlRevocationChecker crlRevocationChecker) {
    }
}
