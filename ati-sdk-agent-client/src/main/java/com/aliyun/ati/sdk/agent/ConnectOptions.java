package com.aliyun.ati.sdk.agent;

/**
 * Configuration options for establishing a verified connection to an ATI agent.
 *
 * <p>Uses the builder pattern with sensible defaults:
 * <ul>
 *   <li>{@code policy} — {@link VerificationPolicy#GOLD}</li>
 *   <li>{@code port} — 443</li>
 *   <li>{@code keystorePath} — {@code null} (no mTLS)</li>
 *   <li>{@code keystorePassword} — {@code null}</li>
 * </ul>
 *
 * <h2>Usage</h2>
 * <pre>{@code
 * ConnectOptions options = ConnectOptions.builder()
 *     .policy(VerificationPolicy.SILVER)
 *     .port(8443)
 *     .keystorePath("/path/to/keystore.p12")
 *     .keystorePassword("secret")
 *     .build();
 * }</pre>
 */
public final class ConnectOptions {

    private final VerificationPolicy policy;
    private final int port;
    private final String keystorePath;
    private final String keystorePassword;

    private ConnectOptions(Builder builder) {
        this.policy = builder.policy;
        this.port = builder.port;
        this.keystorePath = builder.keystorePath;
        this.keystorePassword = builder.keystorePassword;
    }

    /**
     * Returns the verification policy.
     *
     * @return the verification policy
     */
    public VerificationPolicy getPolicy() {
        return policy;
    }

    /**
     * Returns the target port.
     *
     * @return the port number
     */
    public int getPort() {
        return port;
    }

    /**
     * Returns the PKCS12 keystore path for client certificate (mTLS).
     *
     * @return the keystore path, or {@code null} if not configured
     */
    public String getKeystorePath() {
        return keystorePath;
    }

    /**
     * Returns the keystore password.
     *
     * @return the keystore password, or {@code null} if not configured
     */
    public String getKeystorePassword() {
        return keystorePassword;
    }

    /**
     * Creates a new builder with default values.
     *
     * @return a new builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for {@link ConnectOptions}.
     */
    public static final class Builder {

        private VerificationPolicy policy = VerificationPolicy.GOLD;
        private int port = 443;
        private String keystorePath;
        private String keystorePassword;

        private Builder() {
        }

        /**
         * Sets the verification policy.
         *
         * @param policy the verification policy
         * @return this builder
         */
        public Builder policy(VerificationPolicy policy) {
            this.policy = policy;
            return this;
        }

        /**
         * Sets the target port.
         *
         * @param port the port number
         * @return this builder
         */
        public Builder port(int port) {
            this.port = port;
            return this;
        }

        /**
         * Sets the PKCS12 keystore path for client certificate (mTLS).
         *
         * @param keystorePath the keystore path
         * @return this builder
         */
        public Builder keystorePath(String keystorePath) {
            this.keystorePath = keystorePath;
            return this;
        }

        /**
         * Sets the keystore password.
         *
         * @param keystorePassword the keystore password
         * @return this builder
         */
        public Builder keystorePassword(String keystorePassword) {
            this.keystorePassword = keystorePassword;
            return this;
        }

        /**
         * Builds the {@link ConnectOptions} instance.
         *
         * @return a new ConnectOptions
         */
        public ConnectOptions build() {
            return new ConnectOptions(this);
        }
    }
}
