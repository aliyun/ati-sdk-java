package com.aliyun.ati.sdk.agent;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;

import com.aliyun.ati.sdk.agent.http.AtiVerifiedSslContextFactory;
import com.aliyun.ati.sdk.agent.verification.DefaultConnectionVerifier;
import com.aliyun.ati.sdk.agent.verification.VerificationResult;
import com.aliyun.ati.sdk.discovery.AtiAgentDescriptor;
import com.aliyun.ati.sdk.discovery.AtiDiscoveryClient;
import com.aliyun.ati.sdk.discovery.AtiName;
import com.aliyun.ati.sdk.exception.AtiException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Main entry point for establishing verified connections to ATI agents.
 *
 * <p>Orchestrates the full connection flow:
 * <ol>
 *   <li>DNS discovery via {@link AtiDiscoveryClient}</li>
 *   <li>TLS connection with certificate capture via
 *       {@link AtiVerifiedSslContextFactory}</li>
 *   <li>Post-handshake DANE and/or Badge verification via
 *       {@link DefaultConnectionVerifier}</li>
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
 * }</pre>
 */
public final class AtiVerifiedClient {

    private static final Logger LOG =
        LoggerFactory.getLogger(AtiVerifiedClient.class);

    private final AtiDiscoveryClient discoveryClient;
    private final DefaultConnectionVerifier connectionVerifier;
    private final String identityCertificatePath;
    private final String identityPrivateKeyPath;

    private AtiVerifiedClient(Builder builder) {
        this.discoveryClient = Objects.requireNonNull(
            builder.discoveryClient,
            "discoveryClient must not be null");
        this.connectionVerifier = Objects.requireNonNull(
            builder.connectionVerifier,
            "connectionVerifier must not be null");
        this.identityCertificatePath = builder.identityCertificatePath;
        this.identityPrivateKeyPath = builder.identityPrivateKeyPath;
    }

    /**
     * Connects to an ATI agent using default options.
     *
     * @param name the ATI name to connect to
     * @return the verified connection
     * @throws AtiException if connection or verification fails
     */
    public AtiConnection connect(AtiName name) {
        return connect(name, ConnectOptions.builder().build());
    }

    /**
     * Connects to an ATI agent with the specified options.
     *
     * <p>The connection flow:
     * <ol>
     *   <li>Discover the agent via DNS</li>
     *   <li>Create an SSL context with certificate capture</li>
     *   <li>Build an {@link HttpClient} with the SSL context</li>
     *   <li>Trigger a TLS handshake to capture the server cert</li>
     *   <li>Post-verify the captured cert (DANE + Badge)</li>
     *   <li>Return the verified {@link AtiConnection}</li>
     * </ol>
     *
     * @param name    the ATI name to connect to
     * @param options the connection options
     * @return the verified connection
     * @throws AtiException if connection or verification fails
     */
    public AtiConnection connect(AtiName name, ConnectOptions options) {
        Objects.requireNonNull(name, "name must not be null");
        Objects.requireNonNull(options, "options must not be null");

        LOG.info("Connecting to ATI agent: {}", name);

        // Step 1: Discover agent
        AtiAgentDescriptor descriptor = discoveryClient.discover(name);
        LOG.debug("Discovered agent: {}", descriptor);

        // Step 2: Create SSL context with system CA trust + mTLS identity
        AtiVerifiedSslContextFactory.Result sslResult =
            AtiVerifiedSslContextFactory.create(
                identityCertificatePath,
                identityPrivateKeyPath);

        // Step 3: Build HttpClient
        HttpClient httpClient = HttpClient.newBuilder()
            .sslContext(sslResult.getSslContext())
            .build();

        // Step 4: Trigger TLS handshake to capture server cert
        String url = "https://" + descriptor.getAgentHost()
            + ":" + options.getPort();
        triggerHandshake(httpClient, url);

        // Step 5: Get captured cert
        X509Certificate serverCert =
            sslResult.getTrustManager().getLastCapturedServerCert();
        if (serverCert == null) {
            throw new AtiException(
                "Failed to capture server certificate from "
                    + descriptor.getAgentHost());
        }

        // Step 6: Post-verify (DANE + Badge)
        List<VerificationResult> results =
            connectionVerifier.verify(
                descriptor, serverCert, options.getPolicy());

        LOG.info("Connected to ATI agent: {} with {} verification(s)",
            name, results.size());
        return new AtiConnection(httpClient, descriptor, results);
    }

    private void triggerHandshake(HttpClient httpClient, String baseUrl) {
        try {
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(
                    baseUrl + "/.well-known/ati/trust-card.json"))
                .method("HEAD", HttpRequest.BodyPublishers.noBody())
                .build();
            httpClient.send(request,
                HttpResponse.BodyHandlers.discarding());
        } catch (Exception e) {
            LOG.debug(
                "Handshake probe completed (response ignored): {}",
                e.getMessage());
        }
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
