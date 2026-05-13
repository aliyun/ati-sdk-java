package com.aliyun.ati.sdk.config;

import com.aliyun.ati.sdk.auth.AtiCredentialsProvider;

import java.time.Duration;
import java.util.Objects;

public final class AtiConfiguration {

    private static final Duration DEFAULT_CONNECT_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration DEFAULT_READ_TIMEOUT = Duration.ofSeconds(30);
    private static final int DEFAULT_MAX_RETRIES = 3;

    private final Environment environment;
    private final String baseUrl;
    private final AtiCredentialsProvider credentialsProvider;
    private final Duration connectTimeout;
    private final Duration readTimeout;
    private final int maxRetries;

    private AtiConfiguration(Builder builder) {
        this.environment = builder.environment;
        this.baseUrl = builder.baseUrl != null
            ? builder.baseUrl : builder.environment.getBaseUrl();
        this.credentialsProvider = Objects.requireNonNull(builder.credentialsProvider,
            "Credentials provider is required");
        this.connectTimeout = builder.connectTimeout != null
            ? builder.connectTimeout : DEFAULT_CONNECT_TIMEOUT;
        this.readTimeout = builder.readTimeout != null
            ? builder.readTimeout : DEFAULT_READ_TIMEOUT;
        this.maxRetries = builder.maxRetries;
    }

    public static Builder builder() {
        return new Builder();
    }

    public Environment getEnvironment() {
        return environment;
    }

    public String getBaseUrl() {
        return baseUrl;
    }

    public AtiCredentialsProvider getCredentialsProvider() {
        return credentialsProvider;
    }

    public Duration getConnectTimeout() {
        return connectTimeout;
    }

    public Duration getReadTimeout() {
        return readTimeout;
    }

    public int getMaxRetries() {
        return maxRetries;
    }

    public boolean isRetryEnabled() {
        return maxRetries > 0;
    }

    public static final class Builder {

        private Environment environment;
        private String baseUrl;
        private AtiCredentialsProvider credentialsProvider;
        private Duration connectTimeout;
        private Duration readTimeout;
        private int maxRetries = DEFAULT_MAX_RETRIES;

        private Builder() {
        }

        public Builder environment(Environment environment) {
            this.environment = Objects.requireNonNull(environment,
                "Environment cannot be null");
            return this;
        }

        public Builder baseUrl(String baseUrl) {
            this.baseUrl = baseUrl;
            return this;
        }

        public Builder credentialsProvider(AtiCredentialsProvider credentialsProvider) {
            this.credentialsProvider = credentialsProvider;
            return this;
        }

        public Builder connectTimeout(Duration connectTimeout) {
            this.connectTimeout = connectTimeout;
            return this;
        }

        public Builder readTimeout(Duration readTimeout) {
            this.readTimeout = readTimeout;
            return this;
        }

        public Builder maxRetries(int maxRetries) {
            if (maxRetries < 0) {
                throw new IllegalArgumentException("Max retries cannot be negative");
            }
            this.maxRetries = maxRetries;
            return this;
        }

        public AtiConfiguration build() {
            if (this.environment == null) {
                throw new IllegalStateException("Environment is required");
            }
            return new AtiConfiguration(this);
        }
    }
}
