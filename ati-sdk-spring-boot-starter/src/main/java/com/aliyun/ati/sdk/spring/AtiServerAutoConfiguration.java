package com.aliyun.ati.sdk.spring;

import com.aliyun.ati.sdk.agent.server.DefaultClientRequestVerifier;
import com.aliyun.ati.sdk.agent.verification.DaneConfig;
import com.aliyun.ati.sdk.agent.verification.DaneTlsaVerifier;
import com.aliyun.ati.sdk.agent.verification.DefaultDaneTlsaVerifier;
import com.aliyun.ati.sdk.agent.verification.crl.CrlFetcher;
import com.aliyun.ati.sdk.agent.verification.crl.CrlRevocationChecker;
import com.aliyun.ati.sdk.agent.verification.crl.DefaultCrlHttpClient;
import com.aliyun.ati.sdk.transparency.TransparencyClient;
import com.aliyun.ati.sdk.transparency.verification.BadgeVerificationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.Ssl;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.boot.web.servlet.server.ConfigurableServletWebServerFactory;
import org.springframework.context.annotation.Bean;

/**
 * Spring Boot auto-configuration for ATI SDK server-side beans.
 *
 * <p>Activated when {@code ati.sdk.enabled=true} (default) and
 * {@code ati.sdk.mode} is {@code server} or {@code both}.</p>
 *
 * <p>Configures the embedded web server for mTLS with IDCA trust
 * when {@code ati.sdk.server.idca.trust-certificate} is set.</p>
 */
@AutoConfiguration
@ConditionalOnProperty(prefix = "ati.sdk", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(AtiSdkProperties.class)
public class AtiServerAutoConfiguration {

    private static final Logger LOG = LoggerFactory.getLogger(AtiServerAutoConfiguration.class);

    /**
     * Customizes the embedded web server for ATI mTLS.
     *
     * <p>TLS {@code client-auth} is derived from {@code ati.sdk.server.verification.policy}
     * (not configured separately):</p>
     * <ul>
     *   <li>{@code NONE} → {@code client-auth=none}</li>
     *   <li>{@code BASIC} → {@code client-auth=want} (optional IDCA trust store)</li>
     *   <li>{@code ENHANCED}/{@code ADVANCED} → {@code client-auth=need} (IDCA trust store required)</li>
     * </ul>
     *
     * @param properties the ATI SDK properties
     * @return the web server factory customizer
     */
    @Bean
    @ConditionalOnMissingBean
    public WebServerFactoryCustomizer<ConfigurableServletWebServerFactory> atiServerCustomizer(
            AtiSdkProperties properties,
            ObjectProvider<CrlRevocationChecker> crlRevocationCheckerProvider) {

        return factory -> {
            if (!properties.isServerMode()) {
                LOG.debug("Skipping server customization: mode={}", properties.getMode());
                return;
            }

            AtiSdkProperties.Server serverProps = properties.getServer();
            AtiSdkProperties.Idca idcaProps = serverProps.getIdca();
            com.aliyun.ati.sdk.agent.VerificationPolicy policy =
                com.aliyun.ati.sdk.agent.VerificationPolicy.fromString(
                    serverProps.getVerification().getPolicy());

            String trustCert = idcaProps.getTrustCertificate();
            boolean hasIdcaTrust = trustCert != null && !trustCert.isBlank();

            if (policy.requiresIdcaTrust() && !hasIdcaTrust) {
                throw new IllegalStateException(
                    "Server verification policy " + policy + " (" + policy.displayName()
                        + ") requires ati.sdk.server.idca.trust-certificate");
            }

            Ssl ssl = new Ssl();
            ssl.setEnabled(true);
            if (serverProps.getCertificate() != null) {
                ssl.setCertificate(serverProps.getCertificate());
            }
            if (serverProps.getPrivateKey() != null) {
                ssl.setCertificatePrivateKey(serverProps.getPrivateKey());
            }

            switch (policy) {
                case NONE -> {
                    ssl.setClientAuth(Ssl.ClientAuth.NONE);
                    LOG.info("Server policy {}: client-auth=NONE", policy);
                }
                case BASIC -> {
                    ssl.setClientAuth(Ssl.ClientAuth.WANT);
                    if (hasIdcaTrust) {
                        ssl.setTrustCertificate(trustCert);
                    }
                    LOG.info("Server policy {}: client-auth=WANT, idca={}",
                        policy, hasIdcaTrust ? "configured" : "absent");
                }
                case ENHANCED, ADVANCED -> {
                    ssl.setClientAuth(Ssl.ClientAuth.NEED);
                    ssl.setTrustCertificate(trustCert);
                    LOG.info("Server policy {}: client-auth=NEED, idca=configured", policy);
                }
            }

            factory.setSsl(ssl);
            factory.setPort(serverProps.getPort());

            if (shouldInstallCrlChecking(hasIdcaTrust, policy)
                    && factory instanceof TomcatServletWebServerFactory tomcatFactory) {
                CrlRevocationChecker crlRevocationChecker = crlRevocationCheckerProvider.getIfAvailable();
                if (crlRevocationChecker != null) {
                    tomcatFactory.addConnectorCustomizers(
                        new AtiIdcaCrlTomcatCustomizer(crlRevocationChecker));
                    LOG.info("Registered IDCA CRL Tomcat connector customizer for policy={}", policy);
                }
            }

            LOG.info("ATI server configured on port {} with policy={} client-auth={}",
                serverProps.getPort(), policy, ssl.getClientAuth());
        };
    }

    /**
     * CRL revocation checker used at the TLS layer when IDCA trust is configured.
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "ati.sdk", name = "enabled", havingValue = "true", matchIfMissing = true)
    public CrlRevocationChecker crlRevocationChecker() {
        return new CrlRevocationChecker(new CrlFetcher(new DefaultCrlHttpClient()));
    }

    /**
     * Creates a DefaultClientRequestVerifier bean for server-side client verification.
     *
     * <p>Only created when mode is "server" or "both". The verifier uses the
     * {@link BadgeVerificationService} for badge-based client verification
     * when available.</p>
     *
     * @param properties the ATI SDK properties
     * @param badgeVerificationServiceProvider the badge verification service (optional)
     * @return the client request verifier
     */
    /**
     * Creates a BadgeVerificationService bean for server-side client verification.
     *
     * <p>Only created when mode is "server" or "both" and a TransparencyClient
     * is available. The badge service is used by {@link DefaultClientRequestVerifier}
     * to verify client certificates against the transparency log.</p>
     *
     * @param transparencyClient the transparency client (auto-configured by AtiClientAutoConfiguration)
     * @return the badge verification service
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "ati.sdk", name = "enabled", havingValue = "true", matchIfMissing = true)
    public BadgeVerificationService badgeVerificationService(
            ObjectProvider<TransparencyClient> transparencyClientProvider) {
        TransparencyClient transparencyClient = transparencyClientProvider.getIfAvailable();
        if (transparencyClient == null) {
            LOG.warn("TransparencyClient not available, BadgeVerificationService will not be created");
            return null;
        }
        LOG.info("Creating BadgeVerificationService with transparencyClient={}",
            transparencyClient.getClass().getSimpleName());
        return BadgeVerificationService.create(transparencyClient);
    }

    /**
     * Creates a DaneTlsaVerifier bean for DANE-based client verification.
     *
     * <p>Only created when mode is "server" or "both". Used by
     * {@link DefaultClientRequestVerifier} for ADVANCED policy.</p>
     *
     * @param properties the ATI SDK properties
     * @return the DANE TLSA verifier, or null if not in server mode
     */
    @Bean
    @ConditionalOnMissingBean
    public DaneTlsaVerifier daneTlsaVerifier(AtiSdkProperties properties) {
        if (!properties.isServerMode()) {
            LOG.debug("Skipping DaneTlsaVerifier bean: mode={}", properties.getMode());
            return null;
        }
        LOG.info("Creating DaneTlsaVerifier with default config");
        return new DefaultDaneTlsaVerifier(DaneConfig.defaults());
    }

    /**
     * Creates a DefaultClientRequestVerifier bean for server-side client verification.
     *
     * <p>Only created when mode is "server" or "both". The verifier uses the
     * {@link BadgeVerificationService} for badge-based client verification
     * when available, and {@link DaneTlsaVerifier} for DANE verification.</p>
     *
     * @param properties the ATI SDK properties
     * @param badgeVerificationServiceProvider the badge verification service (optional)
     * @param daneTlsaVerifierProvider the DANE TLSA verifier (optional)
     * @return the client request verifier
     */
    @Bean
    @ConditionalOnMissingBean
    public DefaultClientRequestVerifier clientRequestVerifier(
            AtiSdkProperties properties,
            ObjectProvider<BadgeVerificationService> badgeVerificationServiceProvider,
            ObjectProvider<DaneTlsaVerifier> daneTlsaVerifierProvider) {

        if (!properties.isServerMode()) {
            LOG.debug("Skipping DefaultClientRequestVerifier bean: mode={}", properties.getMode());
            return null;
        }

        BadgeVerificationService badgeService = badgeVerificationServiceProvider.getIfAvailable();
        DaneTlsaVerifier daneTlsaVerifier = daneTlsaVerifierProvider.getIfAvailable();
        LOG.info("Creating DefaultClientRequestVerifier with policy={}, badgeService={}, daneTlsaVerifier={}",
            properties.getServer().getVerification().getPolicy(),
            badgeService != null ? "present" : "absent",
            daneTlsaVerifier != null ? "present" : "absent");

        DefaultClientRequestVerifier.Builder builder = DefaultClientRequestVerifier.builder();
        if (badgeService != null) {
            builder.badgeVerificationService(badgeService);
        }
        if (daneTlsaVerifier != null) {
            builder.daneTlsaVerifier(daneTlsaVerifier);
        }
        return builder.build();
    }

    static boolean shouldInstallCrlChecking(
            boolean hasIdcaTrust,
            com.aliyun.ati.sdk.agent.VerificationPolicy policy) {
        return hasIdcaTrust && policy != com.aliyun.ati.sdk.agent.VerificationPolicy.NONE;
    }
}
