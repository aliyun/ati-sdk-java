package com.aliyun.ati.sdk.agent;

import java.net.http.HttpClient;
import java.util.Objects;

import com.aliyun.ati.sdk.agent.http.AtiVerifiedSslContextFactory;
import com.aliyun.ati.sdk.agent.verification.DefaultConnectionVerifier;
import com.aliyun.ati.sdk.agent.verification.PreVerificationResult;
import com.aliyun.ati.sdk.discovery.AtiAgentDescriptor;
import com.aliyun.ati.sdk.discovery.AtiDiscoveryClient;
import com.aliyun.ati.sdk.discovery.AtiName;
import com.aliyun.ati.sdk.exception.AtiException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Main entry point for establishing verified connections to ATI agents.
 *
 * <p>Orchestrates the pre-verify connection flow:
 * <ol>
 *   <li>DNS discovery via {@link AtiDiscoveryClient}</li>
 *   <li>Pre-verify: DNS (DANE TLSA) + Transparency Log (Badge) queries</li>
 *   <li>Create SSL context with certificate capture</li>
 *   <li>Build an {@link HttpClient} (no TLS handshake yet)</li>
 *   <li>Return an {@link AtiConnection} — the caller sends a business
 *       request, then calls {@link AtiConnection#verify()} to
 *       post-verify</li>
 * </ol>
 *
 * <h2>Usage</h2>
 * <pre>{@code
 * AtiVerifiedClient client = AtiVerifiedClient.builder()
 *     .discoveryClient(discoveryClient)
 *     .connectionVerifier(connectionVerifier)
 *     .build();
 *
 * AtiConnection conn = client.connect(
 *     AtiName.parse("ati://v1.agent.example.com"));
 * HttpClient httpClient = conn.getHttpClient();
 * // send a business request ...
 * List<VerificationResult> results = conn.verify();
 * }</pre>
 */
public final class AtiVerifiedClient {

    private static final Logger LOG =
        LoggerFactory.getLogger(AtiVerifiedClient.class);

    private final AtiDiscoveryClient discoveryClient;
    private final DefaultConnectionVerifier connectionVerifier;
    private final String identityCertificatePath;
    private final String identityPrivateKeyPath;
    private final VerificationPolicy defaultPolicy;

    private AtiVerifiedClient(Builder builder) {
        this.discoveryClient = Objects.requireNonNull(
            builder.discoveryClient,
            "discoveryClient must not be null");
        this.connectionVerifier = Objects.requireNonNull(
            builder.connectionVerifier,
            "connectionVerifier must not be null");
        this.identityCertificatePath = builder.identityCertificatePath;
        this.identityPrivateKeyPath = builder.identityPrivateKeyPath;
        this.defaultPolicy = builder.defaultPolicy;
    }

    /**
     * Connects to an ATI agent using the default policy.
     *
     * @param name the ATI name to connect to
     * @return the pre-verified connection
     * @throws AtiException if discovery or pre-verification fails
     */
    public AtiConnection connect(AtiName name) {
        return connect(name, ConnectOptions.builder()
            .policy(defaultPolicy).build());
    }

    /**
     * Connects to an ATI agent with the specified options.
     *
     * <p>The connection flow:
     * <ol>
     *   <li>Discover the agent via DNS</li>
     *   <li>Pre-verify: query DANE TLSA records and Badge TL</li>
     *   <li>Create an SSL context with certificate capture</li>
     *   <li>Build an {@link HttpClient} (no TLS handshake yet)</li>
     *   <li>Return the {@link AtiConnection} — call
     *       {@link AtiConnection#verify()} after sending a request</li>
     * </ol>
     *
     * @param name    the ATI name to connect to
     * @param options the connection options
     * @return the pre-verified connection
     * @throws AtiException if discovery or pre-verification fails
     */
    public AtiConnection connect(AtiName name, ConnectOptions options) {
        Objects.requireNonNull(name, "name must not be null");
        Objects.requireNonNull(options, "options must not be null");

        LOG.info("Connecting to ATI agent: {}", name);

        // Step 1: Discover
        AtiAgentDescriptor descriptor =
            discoveryClient.discover(name);
        LOG.debug("Discovered agent: {}", descriptor);

        // Step 2: Pre-verify (DNS + TL queries, no TLS handshake)
        PreVerificationResult preResult =
            connectionVerifier.preVerify(
                descriptor, options.getPolicy(), options.getPort());

        // Step 3: Create SSL context
        AtiVerifiedSslContextFactory.Result sslResult =
            AtiVerifiedSslContextFactory.create(
                identityCertificatePath,
                identityPrivateKeyPath);

        // Step 4: Build HttpClient (no TLS handshake yet)
        HttpClient httpClient = HttpClient.newBuilder()
            .sslContext(sslResult.getSslContext())
            .build();

        LOG.info("Pre-verified ATI agent: {}", name);
        return new AtiConnection(httpClient, descriptor, preResult,
            connectionVerifier, sslResult.getTrustManager());
    }

    /**
     * Creates a new builder.
     *
     * @return a new builder
     */
    public static Builder builder() {
        return new Builder();
    }

    /**
     * Builder for {@link AtiVerifiedClient}.
     */
    public static final class Builder {

        private AtiDiscoveryClient discoveryClient;
        private DefaultConnectionVerifier connectionVerifier;
        private String identityCertificatePath;
        private String identityPrivateKeyPath;
        private VerificationPolicy defaultPolicy = VerificationPolicy.GOLD;

        private Builder() {
        }

        /**
         * Sets the discovery client for resolving ATI names.
         *
         * @param discoveryClient the discovery client
         * @return this builder
         */
        public Builder discoveryClient(
                AtiDiscoveryClient discoveryClient) {
            this.discoveryClient = discoveryClient;
            return this;
        }

        /**
         * Sets the connection verifier for post-handshake verification.
         *
         * @param connectionVerifier the connection verifier
         * @return this builder
         */
        public Builder connectionVerifier(
                DefaultConnectionVerifier connectionVerifier) {
            this.connectionVerifier = connectionVerifier;
            return this;
        }

        /**
         * Sets the path to the PEM-encoded identity certificate for mTLS.
         *
         * <p>Both {@code identityCertificatePath} and
         * {@code identityPrivateKeyPath} must be set together for mTLS,
         * or both left {@code null} for server-only authentication.</p>
         *
         * @param identityCertificatePath path to the PEM certificate
         *                                (supports {@code classpath:} prefix)
         * @return this builder
         */
        public Builder identityCertificatePath(
                String identityCertificatePath) {
            this.identityCertificatePath = identityCertificatePath;
            return this;
        }

        /**
         * Sets the path to the PEM-encoded PKCS8 private key for mTLS.
         *
         * <p>Both {@code identityCertificatePath} and
         * {@code identityPrivateKeyPath} must be set together for mTLS,
         * or both left {@code null} for server-only authentication.</p>
         *
         * @param identityPrivateKeyPath path to the PEM private key
         *                               (supports {@code classpath:} prefix)
         * @return this builder
         */
        public Builder identityPrivateKeyPath(
                String identityPrivateKeyPath) {
            this.identityPrivateKeyPath = identityPrivateKeyPath;
            return this;
        }

        /**
         * Sets the default verification policy used by {@link #connect(AtiName)}.
         *
         * @param defaultPolicy the default policy (default: GOLD)
         * @return this builder
         */
        public Builder defaultPolicy(VerificationPolicy defaultPolicy) {
            this.defaultPolicy = Objects.requireNonNull(defaultPolicy,
                "defaultPolicy must not be null");
            return this;
        }

        /**
         * Builds the {@link AtiVerifiedClient} instance.
         *
         * @return a new AtiVerifiedClient
         * @throws NullPointerException if required dependencies are null
         */
        public AtiVerifiedClient build() {
            return new AtiVerifiedClient(this);
        }
    }
}
