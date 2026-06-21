package com.aliyun.ati.sdk.agent;

import com.aliyun.ati.sdk.agent.connection.AgentConnection;
import com.aliyun.ati.sdk.agent.http.AgentHttpClientFactory;
import com.aliyun.ati.sdk.agent.http.DefaultAgentHttpClientFactory;
import com.aliyun.ati.sdk.agent.http.VerifiedClientResult;
import com.aliyun.ati.sdk.agent.verification.DaneTlsaVerifier;
import com.aliyun.ati.sdk.model.generated.AgentDetails;
import com.aliyun.ati.sdk.model.generated.AgentLifecycleStatus;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.time.Duration;
import java.util.Objects;

/**
 * Client for connecting to ATI-registered agents with configurable verification.
 *
 * <p>This is the main entry point for agent-to-agent communication. Use
 * {@code DiscoveryClient} from the discovery module separately for agent
 * resolution if needed.</p>
 *
 * <h2>Quick Start - Request/Response</h2>
 * <pre>{@code
 * // Create client with default settings
 * AtiClient client = AtiClient.create();
 *
 * // Connect with badge verification (recommended)
 * AgentConnection conn = client.connect("https://agent.example.com",
 *     ConnectOptions.builder()
 *         .verificationPolicy(VerificationPolicy.BADGE_REQUIRED)
 *         .build());
 *
 * // Use the connection
 * String response = conn.httpApiAt("https://agent.example.com").get("/api/v1/data");
 * }</pre>
 *
 * <h2>Verification Methods</h2>
 * <ul>
 *   <li><b>DANE</b>: DNS-based TLSA record verification (requires DNSSEC)</li>
 *   <li><b>Badge</b>: ATI transparency log verification (proof of registration)</li>
 * </ul>
 *
 * @see VerificationPolicy
 * @see VerificationMode
 * @see ConnectOptions
 */
public final class AtiClient {

    private static final Logger LOGGER = LoggerFactory.getLogger(AtiClient.class);
    private static final Duration DEFAULT_CONNECT_TIMEOUT = Duration.ofSeconds(10);
    private static final Duration DEFAULT_READ_TIMEOUT = Duration.ofSeconds(30);

    private final AgentHttpClientFactory httpClientFactory;
    private final Duration connectTimeout;
    private final Duration readTimeout;

    private AtiClient(AgentHttpClientFactory httpClientFactory,
                      Duration connectTimeout,
                      Duration readTimeout) {
        this.httpClientFactory = httpClientFactory;
        this.connectTimeout = connectTimeout;
        this.readTimeout = readTimeout;
    }

    // ==================== Factory Methods ====================

    /**
     * Creates an AtiClient with default settings.
     *
     * @return a new AtiClient
     */
    public static AtiClient create() {
        return new AtiClient(
            AgentHttpClientFactory.createDefault(),
            DEFAULT_CONNECT_TIMEOUT,
            DEFAULT_READ_TIMEOUT
        );
    }

    /**
     * Creates a builder for more control over client configuration.
     *
     * @return a new builder
     */
    public static Builder builder() {
        return new Builder();
    }

    // ==================== Connection Methods ====================

    /**
     * Connects to an agent at the specified URL.
     *
     * <p>Use this when you know the exact URL of the agent you want to connect to.</p>
     *
     * @param url the target URL
     * @return an AgentConnection
     */
    public AgentConnection connect(String url) {
        return connect(url, ConnectOptions.defaults());
    }

    /**
     * Connects to an agent at the specified URL with custom options.
     *
     * <p>Verification is performed outside the TLS handshake for better performance:</p>
     * <ol>
     *   <li>Pre-verify: Look up DANE/Badge expectations (cached)</li>
     *   <li>TLS handshake: PKI-only validation (fast)</li>
     *   <li>Post-verify: Compare cert to expectations</li>
     * </ol>
     *
     * @param url the target URL
     * @param options connection options (verification policy, client cert, etc.)
     * @return an AgentConnection
     */
    public AgentConnection connect(String url, ConnectOptions options) {
        Objects.requireNonNull(url, "URL cannot be null");
        Objects.requireNonNull(options, "Connect options cannot be null");

        URI uri = URI.create(url);
        String hostname = uri.getHost();

        VerificationPolicy policy = options.getVerificationPolicy();
        LOGGER.debug("Connecting to: {} with verification policy: {}", url, policy);

        // Build verified HTTP client (verification outside handshake)
        VerifiedClientResult result = buildVerifiedClient(hostname, options);

        // Create agent details for the connection
        AgentDetails agentDetails = createAgentDetails(hostname);

        // Pass the verifying client to the connection for verified requests
        return new AgentConnection(agentDetails, result.atiHttpClient(), readTimeout, options.getAuthProvider());
    }

    // ==================== Private Helpers ====================

    /**
     * Builds a verified HTTP client with trust configuration based on options.
     *
     * <p>Returns a {@link VerifiedClientResult} containing:</p>
     * <ul>
     *   <li>The underlying HttpClient (PKI-only with certificate capture)</li>
     *   <li>The ConnectionVerifier for DANE/Badge verification</li>
     *   <li>The AtiHttpClient that orchestrates verification</li>
     * </ul>
     */
    private VerifiedClientResult buildVerifiedClient(String hostname, ConnectOptions options) {
        return httpClientFactory.createVerified(hostname, options, connectTimeout);
    }

    /**
     * Creates placeholder agent details for direct connections.
     *
     * <p>When connecting directly to a URL (without ANS resolution), we don't have
     * the full agent details from the registry. This creates a minimal placeholder
     * with the hostname extracted from the URL.</p>
     *
     * <p>Note: The atiName is not set since this is not an ANS-resolved connection.
     * Use {@link com.aliyun.ati.sdk.discovery.DiscoveryClient} to resolve agents
     * and get full details including the proper ANS name.</p>
     *
     * @param hostname the hostname extracted from the connection URL
     * @return placeholder agent details
     */
    private AgentDetails createAgentDetails(String hostname) {
        AgentDetails details = new AgentDetails();
        details.setAgentHost(hostname);
        details.setAgentStatus(AgentLifecycleStatus.ACTIVE);
        return details;
    }

    // ==================== Builder ====================

    /**
     * Builder for AtiClient with additional configuration options.
     */
    public static final class Builder {
        private AgentHttpClientFactory httpClientFactory;
        private DaneTlsaVerifier daneVerifier;
        private Duration connectTimeout = DEFAULT_CONNECT_TIMEOUT;
        private Duration readTimeout = DEFAULT_READ_TIMEOUT;

        private Builder() {
        }

        /**
         * Sets a custom HTTP client factory.
         *
         * <p>Use this for testing or when you need complete control over
         * HttpClient creation. If not set, a default factory is used.</p>
         *
         * @param factory the HTTP client factory
         * @return this builder
         */
        public Builder httpClientFactory(AgentHttpClientFactory factory) {
            this.httpClientFactory = factory;
            return this;
        }

        /**
         * Sets a custom DANE verifier.
         *
         * <p>This is ignored if a custom httpClientFactory is set.</p>
         *
         * @param daneVerifier the DANE verifier
         * @return this builder
         */
        public Builder daneVerifier(DaneTlsaVerifier daneVerifier) {
            this.daneVerifier = daneVerifier;
            return this;
        }

        /**
         * Sets the connection timeout.
         *
         * @param timeout the timeout
         * @return this builder
         */
        public Builder connectTimeout(Duration timeout) {
            this.connectTimeout = timeout;
            return this;
        }

        /**
         * Sets the read timeout.
         *
         * @param timeout the timeout
         * @return this builder
         */
        public Builder readTimeout(Duration timeout) {
            this.readTimeout = timeout;
            return this;
        }

        /**
         * Builds the AtiClient.
         *
         * @return a new AtiClient instance
         */
        public AtiClient build() {
            AgentHttpClientFactory factory = httpClientFactory;
            if (factory == null) {
                // Create default factory, optionally with custom DANE verifier
                if (daneVerifier != null) {
                    factory = new DefaultAgentHttpClientFactory(daneVerifier);
                } else {
                    factory = AgentHttpClientFactory.createDefault();
                }
            }

            return new AtiClient(
                factory,
                connectTimeout,
                readTimeout
            );
        }
    }
}