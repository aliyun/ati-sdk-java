package com.aliyun.ati.sdk.spring;

import com.aliyun.ati.sdk.config.Environment;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * Configuration properties for ATI SDK.
 *
 * <p>Properties are bound from the {@code ati} prefix in application properties.</p>
 *
 * <p>Example {@code application.yml}:</p>
 * <pre>
 * ati:
 *   environment: OTE
 *   connect-timeout: 15s
 *   read-timeout: 45s
 *   max-retries: 5
 * </pre>
 */
@ConfigurationProperties(prefix = "ati")
public class AtiProperties {

    /**
     * ATI environment (OTE or PROD). Required.
     */
    private Environment environment;

    /**
     * Custom base URL. Overrides the environment's default URL when set.
     */
    private String baseUrl;

    /**
     * Connection timeout. Defaults to SDK default (10s) if not set.
     */
    private Duration connectTimeout;

    /**
     * Read timeout. Defaults to SDK default (30s) if not set.
     */
    private Duration readTimeout;

    /**
     * Maximum number of retry attempts. Defaults to SDK default (3) if not set.
     */
    private Integer maxRetries;

    /**
     * Whether auto-configuration is enabled. Defaults to true.
     */
    private boolean enabled = true;

    public Environment getEnvironment() {
        return environment;
    }

    public void setEnvironment(Environment environment) {
        this.environment = environment;
    }

    public String getBaseUrl() {
        return baseUrl;
    }

    public void setBaseUrl(String baseUrl) {
        this.baseUrl = baseUrl;
    }

    public Duration getConnectTimeout() {
        return connectTimeout;
    }

    public void setConnectTimeout(Duration connectTimeout) {
        this.connectTimeout = connectTimeout;
    }

    public Duration getReadTimeout() {
        return readTimeout;
    }

    public void setReadTimeout(Duration readTimeout) {
        this.readTimeout = readTimeout;
    }

    public Integer getMaxRetries() {
        return maxRetries;
    }

    public void setMaxRetries(Integer maxRetries) {
        this.maxRetries = maxRetries;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }
}
