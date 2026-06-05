package com.aliyun.ati.sdk.agent;

/**
 * Configuration options for establishing a verified connection to an ATI agent.
 *
 * <p>Uses the builder pattern with sensible defaults:
 * <ul>
 *   <li>{@code policy} — {@link VerificationPolicy#GOLD}</li>
 *   <li>{@code port} — 443</li>
 * </ul>
 *
 * <p>Identity certificate (mTLS) is configured globally on
 * {@link AtiVerifiedClient.Builder}, not per-connection.
 */
public final class ConnectOptions {

    private final VerificationPolicy policy;
    private final int port;

    private ConnectOptions(Builder builder) {
        this.policy = builder.policy;
        this.port = builder.port;
    }

    public VerificationPolicy getPolicy() {
        return policy;
    }

    public int getPort() {
        return port;
    }

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {

        private VerificationPolicy policy = VerificationPolicy.GOLD;
        private int port = 443;

        private Builder() {
        }

        public Builder policy(VerificationPolicy policy) {
            this.policy = policy;
            return this;
        }

        public Builder port(int port) {
            this.port = port;
            return this;
        }

        public ConnectOptions build() {
            return new ConnectOptions(this);
        }
    }
}
