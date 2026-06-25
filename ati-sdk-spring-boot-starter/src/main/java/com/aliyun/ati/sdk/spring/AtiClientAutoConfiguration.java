package com.aliyun.ati.sdk.spring;

import com.aliyun.ati.sdk.agent.AtiClient;
import com.aliyun.ati.sdk.agent.AtiVerifiedClient;
import com.aliyun.ati.sdk.agent.VerificationPolicy;
import com.aliyun.ati.sdk.discovery.AtiDiscoveryClient;
import com.aliyun.ati.sdk.transparency.TransparencyClient;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

import java.time.Duration;

/**
 * Spring Boot auto-configuration for ATI SDK client-side beans.
 *
 * <p>Activated when {@code ati.sdk.enabled=true} (default) and
 * {@code ati.sdk.mode} is {@code client} or {@code both}.</p>
 *
 * <p>Creates {@link TransparencyClient} and {@link AtiClient} beans
 * configured from {@code ati.sdk.*} application properties.</p>
 */
@AutoConfiguration
@ConditionalOnProperty(prefix = "ati.sdk", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(AtiSdkProperties.class)
public class AtiClientAutoConfiguration {

    private static final Logger LOG = LoggerFactory.getLogger(AtiClientAutoConfiguration.class);

    /**
     * Creates a TransparencyClient bean from properties.
     *
     * @param properties the ATI SDK properties
     * @return the transparency client
     */
    @Bean
    @ConditionalOnMissingBean
    public TransparencyClient transparencyClient(AtiSdkProperties properties) {
        String baseUrl = properties.getTransparency().getBaseUrl();
        LOG.info("Creating TransparencyClient with baseUrl={}", baseUrl);

        TransparencyClient.Builder builder = TransparencyClient.builder()
            .baseUrl(baseUrl)
            .skipTlsVerification(properties.getTransparency().isSkipTlsVerification());

        String connectTimeout = properties.getClient().getConnectTimeout();
        if (connectTimeout != null) {
            builder.connectTimeout(parseDuration(connectTimeout));
        }

        return builder.build();
    }

    /**
     * Creates an AtiClient bean for agent-to-agent communication.
     *
     * <p>Only created when mode is "client" or "both".</p>
     *
     * @param properties the ATI SDK properties
     * @return the ATI client
     */
    @Bean
    @ConditionalOnMissingBean
    public AtiClient atiClient(AtiSdkProperties properties) {
        if (!properties.isClientMode()) {
            LOG.debug("Skipping AtiClient bean: mode={}", properties.getMode());
            return null;
        }

        AtiClient.Builder builder = AtiClient.builder();

        String connectTimeout = properties.getClient().getConnectTimeout();
        if (connectTimeout != null) {
            builder.connectTimeout(parseDuration(connectTimeout));
        }

        return builder.build();
    }

    /**
     * Creates an AtiDiscoveryClient bean for agent resolution via Alibaba Cloud OpenAPI.
     *
     * <p>Only created when mode is "client" or "both" and discovery credentials are configured.</p>
     *
     * @param properties the ATI SDK properties
     * @return the discovery client
     * @throws Exception if the OpenAPI client cannot be created
     */
    @Bean
    @ConditionalOnMissingBean
    public AtiDiscoveryClient atiDiscoveryClient(AtiSdkProperties properties) throws Exception {
        if (!properties.isClientMode()) {
            LOG.debug("Skipping AtiDiscoveryClient bean: mode={}", properties.getMode());
            return null;
        }

        AtiSdkProperties.Discovery discovery = properties.getDiscovery();
        LOG.info("Creating AtiDiscoveryClient with endpoint={}", discovery.getEndpoint());
        return new AtiDiscoveryClient(
            discovery.getEndpoint(),
            discovery.getAccessKeyId(),
            discovery.getAccessKeySecret());
    }

    /**
     * Creates an AtiVerifiedClient bean for verified agent-to-agent connections.
     *
     * <p>Only created when mode is "client" or "both".</p>
     *
     * @param properties the ATI SDK properties
     * @param transparencyClient the transparency client for badge verification
     * @return the verified client
     */
    @Bean
    @ConditionalOnMissingBean
    public AtiVerifiedClient atiVerifiedClient(AtiSdkProperties properties,
                                               TransparencyClient transparencyClient) {
        if (!properties.isClientMode()) {
            LOG.debug("Skipping AtiVerifiedClient bean: mode={}", properties.getMode());
            return null;
        }

        String policyStr = properties.getVerification().getPolicy();
        VerificationPolicy policy = VerificationPolicy.valueOf(policyStr);

        AtiVerifiedClient.Builder builder = AtiVerifiedClient.builder()
            .transparencyClient(transparencyClient)
            .policy(policy);

        String connectTimeout = properties.getClient().getConnectTimeout();
        if (connectTimeout != null) {
            builder.connectTimeout(parseDuration(connectTimeout));
        }

        LOG.info("Creating AtiVerifiedClient with policy={}", policy);
        return builder.build();
    }

    /**
     * Parses a duration string like "5s", "10s", "500ms".
     */
    private static Duration parseDuration(String value) {
        if (value == null || value.isBlank()) {
            return Duration.ofSeconds(10);
        }
        // Support simple formats: "5s", "10s", "500ms"
        value = value.trim().toLowerCase();
        if (value.endsWith("ms")) {
            return Duration.ofMillis(
                Long.parseLong(value.substring(0, value.length() - 2)));
        } else if (value.endsWith("s")) {
            return Duration.ofSeconds(
                Long.parseLong(value.substring(0, value.length() - 1)));
        } else if (value.endsWith("m")) {
            return Duration.ofMinutes(
                Long.parseLong(value.substring(0, value.length() - 1)));
        }
        return Duration.ofSeconds(Long.parseLong(value));
    }
}
