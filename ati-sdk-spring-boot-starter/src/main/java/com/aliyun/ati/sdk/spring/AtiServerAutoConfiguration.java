package com.aliyun.ati.sdk.spring;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
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
                LOG.info("IDCA trust certificate configured: enabling client-auth=need");
                ssl.setClientAuth(Ssl.ClientAuth.NEED);
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
}
