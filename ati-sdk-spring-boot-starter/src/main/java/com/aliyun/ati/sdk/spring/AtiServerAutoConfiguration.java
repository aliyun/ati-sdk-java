package com.aliyun.ati.sdk.spring;

import com.aliyun.ati.sdk.agent.server.DefaultClientRequestVerifier;
import com.aliyun.ati.sdk.agent.verification.DaneConfig;
import com.aliyun.ati.sdk.agent.verification.DaneTlsaVerifier;
import com.aliyun.ati.sdk.agent.verification.DefaultDaneTlsaVerifier;
import com.aliyun.ati.sdk.transparency.TransparencyClient;
import com.aliyun.ati.sdk.transparency.verification.BadgeVerificationService;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
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
     * <p>When {@code ati.sdk.mode} is {@code server} or {@code both}:</p>
     * <ul>
     *   <li>If {@code ati.sdk.server.idca.trust-certificate} is configured,
     *       sets {@code server.ssl.client-auth=need} and configures
     *       the IDCA trust store for client certificate verification.</li>
     *   <li>If not configured, sets {@code server.ssl.client-auth=want}
     *       to optionally accept client certificates.</li>
     * </ul>
     *
     * @param properties the ATI SDK properties
     * @return the web server factory customizer
     */
    @Bean
    public WebServerFactoryCustomizer<ConfigurableServletWebServerFactory> atiServerCustomizer(
            AtiSdkProperties properties) {

        return factory -> {
            if (!properties.isServerMode()) {
                LOG.debug("Skipping server customization: mode={}", properties.getMode());
                return;
            }

            AtiSdkProperties.Server serverProps = properties.getServer();
            AtiSdkProperties.Idca idcaProps = serverProps.getIdca();

            // Configure server SSL certificate
            Ssl ssl = new Ssl();
            if (serverProps.getCertificate() != null) {
                ssl.setCertificate(serverProps.getCertificate());
            }
            if (serverProps.getPrivateKey() != null) {
                ssl.setCertificatePrivateKey(serverProps.getPrivateKey());
            }

            // Configure client authentication based on IDCA trust certificate
            String trustCert = idcaProps.getTrustCertificate();
            if (trustCert != null && !trustCert.isBlank()) {
                LOG.info("IDCA trust certificate configured: setting client-auth=want");
                ssl.setClientAuth(Ssl.ClientAuth.WANT);
                ssl.setTrustCertificate(trustCert);
            } else {
                LOG.info("No IDCA trust certificate: setting client-auth=want");
                ssl.setClientAuth(Ssl.ClientAuth.WANT);
            }

            factory.setSsl(ssl);
            factory.setPort(serverProps.getPort());

            LOG.info("ATI server configured on port {} with client-auth={}",
                serverProps.getPort(), ssl.getClientAuth());
        };
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
     * {@link DefaultClientRequestVerifier} for DANE_AND_BADGE policy.</p>
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
}
