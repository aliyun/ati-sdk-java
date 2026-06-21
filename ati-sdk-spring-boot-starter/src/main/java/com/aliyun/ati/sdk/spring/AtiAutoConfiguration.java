package com.aliyun.ati.sdk.spring;

import com.aliyun.ati.sdk.agent.AtiClient;
import com.aliyun.ati.sdk.config.AtiConfiguration;
import com.aliyun.ati.sdk.transparency.TransparencyClient;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;

/**
 * Spring Boot auto-configuration for ATI SDK.
 *
 * <p>Automatically creates {@link AtiConfiguration}, {@link TransparencyClient},
 * and {@link AtiClient} beans from {@code ati.*} application properties.</p>
 *
 * <p>This auto-configuration is enabled when {@code ati.enabled} is {@code true} (default).</p>
 *
 * <p>All beans are conditional on missing beans, so users can override
 * any bean by defining their own.</p>
 */
@AutoConfiguration
@ConditionalOnProperty(prefix = "ati", name = "enabled", havingValue = "true", matchIfMissing = true)
@EnableConfigurationProperties(AtiProperties.class)
public class AtiAutoConfiguration {

    /**
     * Creates the ATI configuration from properties.
     *
     * @param properties the ATI properties
     * @return the ATI configuration
     */
    @Bean
    @ConditionalOnMissingBean
    public AtiConfiguration atiConfiguration(AtiProperties properties) {
        if (properties.getEnvironment() == null) {
            throw new IllegalStateException(
                "ati.environment is required. Supported values: OTE, PROD");
        }

        AtiConfiguration.Builder builder = AtiConfiguration.builder()
            .environment(properties.getEnvironment());

        if (properties.getBaseUrl() != null) {
            builder.baseUrl(properties.getBaseUrl());
        }
        if (properties.getConnectTimeout() != null) {
            builder.connectTimeout(properties.getConnectTimeout());
        }
        if (properties.getReadTimeout() != null) {
            builder.readTimeout(properties.getReadTimeout());
        }
        if (properties.getMaxRetries() != null) {
            builder.enableRetry(properties.getMaxRetries());
        }

        return builder.build();
    }

    /**
     * Creates an AtiClient bean for agent-to-agent communication.
     *
     * @return the ATI client
     */
    @Bean
    @ConditionalOnMissingBean
    public AtiClient atiClient() {
        return AtiClient.create();
    }
}
