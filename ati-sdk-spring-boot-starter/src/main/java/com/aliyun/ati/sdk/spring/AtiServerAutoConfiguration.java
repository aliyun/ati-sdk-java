package com.aliyun.ati.sdk.spring;

import com.aliyun.ati.sdk.agent.server.DefaultClientRequestVerifier;
import com.aliyun.ati.sdk.agent.verification.DaneConfig;
import com.aliyun.ati.sdk.agent.verification.DaneTlsaVerifier;
import com.aliyun.ati.sdk.agent.verification.DefaultDaneTlsaVerifier;
import com.aliyun.ati.sdk.agent.verification.IdcaChain;
import com.aliyun.ati.sdk.agent.verification.crl.CrlFetcher;
import com.aliyun.ati.sdk.agent.verification.crl.CrlRevocationChecker;
import com.aliyun.ati.sdk.agent.verification.crl.DefaultCrlHttpClient;
import com.aliyun.ati.sdk.transparency.TransparencyClient;
import com.aliyun.ati.sdk.transparency.verification.BadgeVerificationService;
import com.aliyun.ati.sdk.transparency.verification.SealTrustChain;
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
 * <p>Configures the embedded web server for mTLS. When verification policy is not
 * {@code NONE}, the SDK-shipped production IDCA Chain is the default trust material.
 * {@code ati.sdk.server.idca.trust-certificate} optionally replaces that chain.</p>
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
     *   <li>{@code NONE} → {@code client-auth=none} (IDCA Chain unused)</li>
     *   <li>{@code BASIC}/{@code ENHANCED}/{@code ADVANCED} → {@code client-auth=need}
     *       (shipped IDCA Chain, optional override). A missing Identity Certificate
     *       fails the TLS handshake. This is what distinguishes None from Basic.</li>
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

            String trustOverride = idcaProps.getTrustCertificate();
            boolean hasIdcaTrust = policy.requiresIdcaTrust();
            String trustCert = hasIdcaTrust
                ? IdcaChain.trustCertificateLocation(trustOverride)
                : null;

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
                case BASIC, ENHANCED, ADVANCED -> {
                    ssl.setClientAuth(Ssl.ClientAuth.NEED);
                    ssl.setTrustCertificate(trustCert);
                    LOG.info("Server policy {}: client-auth=NEED, idca={}",
                        policy, trustOverride == null || trustOverride.isBlank() ? "shipped" : "override");
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
            } else if (shouldInstallCrlChecking(hasIdcaTrust, policy)) {
                LOG.warn(
                    "IDCA CRL checking requires embedded Tomcat; current factory={}. "
                        + "Certificate revocation will not run at the TLS layer.",
                    factory.getClass().getSimpleName());
            }

            LOG.info("ATI server configured on port {} with policy={} client-auth={}",
                serverProps.getPort(), policy, ssl.getClientAuth());
        };
    }

    /**
     * CRL revocation checker used at the TLS layer when the IDCA Chain is loaded.
     */
    @Bean
    @ConditionalOnMissingBean
    public CrlRevocationChecker crlRevocationChecker(AtiSdkProperties properties) {
        if (!properties.isServerMode()) {
            LOG.debug("Skipping CrlRevocationChecker bean: mode={}", properties.getMode());
            return null;
        }
        return new CrlRevocationChecker(new CrlFetcher(new DefaultCrlHttpClient()));
    }

    /**
     * Resolves the Seal CA Chain used for Badge pre-verification.
     *
     * <p>Same bean as {@code AtiClientAutoConfiguration#sealTrustChain}: blank/unset uses the
     * shipped chain; a non-blank {@code ati.sdk.transparency.seal.trust-certificate} replaces
     * it wholesale. {@code @ConditionalOnMissingBean} so mode=both shares one instance.</p>
     *
     * @param properties the ATI SDK properties
     * @return the resolved Seal CA Chain
     */
    @Bean
    @ConditionalOnMissingBean
    public SealTrustChain sealTrustChain(AtiSdkProperties properties) {
        String override = properties.getTransparency().getSeal().getTrustCertificate();
        SealTrustChain chain = SealTrustChain.resolve(override);
        LOG.info("Seal CA Chain: {}",
            override == null || override.isBlank() ? "shipped" : "override");
        return chain;
    }

    /**
     * Creates a BadgeVerificationService bean for server-side client verification.
     *
     * <p>Only created when mode is "server" or "both" and a TransparencyClient
     * is available. The badge service is used by {@link DefaultClientRequestVerifier}
     * to verify client certificates against the transparency log.</p>
     *
     * <p>Badge pre-verification anchors Seal signature validation on a {@link SealTrustChain}
     * bean (SDK-shipped production chain by default; {@code ati.sdk.transparency.seal.trust-certificate}
     * optionally replaces it). A malformed override fails closed, so the bean is not created.</p>
     *
     * @param transparencyClientProvider the transparency client (auto-configured by AtiClientAutoConfiguration)
     * @param sealTrustChain the Seal CA Chain for Badge pre-verification
     * @return the badge verification service
     */
    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "ati.sdk", name = "enabled", havingValue = "true", matchIfMissing = true)
    public BadgeVerificationService badgeVerificationService(
            ObjectProvider<TransparencyClient> transparencyClientProvider,
            SealTrustChain sealTrustChain) {
        TransparencyClient transparencyClient = transparencyClientProvider.getIfAvailable();
        if (transparencyClient == null) {
            LOG.warn("TransparencyClient not available, BadgeVerificationService will not be created");
            return null;
        }
        LOG.info("Creating BadgeVerificationService with transparencyClient={}",
            transparencyClient.getClass().getSimpleName());
        return BadgeVerificationService.builder()
            .transparencyClient(transparencyClient)
            .sealTrustChain(sealTrustChain)
            .build();
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
