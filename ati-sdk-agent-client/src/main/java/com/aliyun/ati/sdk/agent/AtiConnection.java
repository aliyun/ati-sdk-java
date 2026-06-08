package com.aliyun.ati.sdk.agent;

import java.net.http.HttpClient;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Objects;

import com.aliyun.ati.sdk.agent.http.CertificateCapturingTrustManager;
import com.aliyun.ati.sdk.agent.verification.DefaultConnectionVerifier;
import com.aliyun.ati.sdk.agent.verification.PreVerificationResult;
import com.aliyun.ati.sdk.agent.verification.VerificationResult;
import com.aliyun.ati.sdk.discovery.AtiAgentDescriptor;
import com.aliyun.ati.sdk.exception.AtiException;

/**
 * Holds a pre-verified connection to an ATI agent.
 *
 * <p>Contains the {@link HttpClient} configured with the SSL context,
 * the {@link AtiAgentDescriptor} from discovery, and the pre-verification
 * state from DNS/TL queries.</p>
 *
 * <p>After sending a request (which triggers the TLS handshake), call
 * {@link #verify()} to compare the captured server certificate against
 * the pre-fetched expectations.</p>
 */
public final class AtiConnection {

    private final HttpClient httpClient;
    private final AtiAgentDescriptor descriptor;
    private final PreVerificationResult preResult;
    private final DefaultConnectionVerifier connectionVerifier;
    private final CertificateCapturingTrustManager trustManager;

    /**
     * Creates a new ATI connection with pre-verification state.
     *
     * @param httpClient          the HTTP client with SSL context
     * @param descriptor          the discovered agent descriptor
     * @param preResult           the pre-verification result
     * @param connectionVerifier  the connection verifier for post-verify
     * @param trustManager        the trust manager capturing server certs
     */
    public AtiConnection(HttpClient httpClient,
                         AtiAgentDescriptor descriptor,
                         PreVerificationResult preResult,
                         DefaultConnectionVerifier connectionVerifier,
                         CertificateCapturingTrustManager trustManager) {
        this.httpClient = Objects.requireNonNull(httpClient,
            "httpClient must not be null");
        this.descriptor = Objects.requireNonNull(descriptor,
            "descriptor must not be null");
        this.preResult = Objects.requireNonNull(preResult,
            "preResult must not be null");
        this.connectionVerifier = Objects.requireNonNull(
            connectionVerifier,
            "connectionVerifier must not be null");
        this.trustManager = Objects.requireNonNull(trustManager,
            "trustManager must not be null");
    }

    /**
     * Post-verifies the server certificate captured during the TLS
     * handshake against the pre-fetched DANE and Badge expectations.
     *
     * <p>Must be called after at least one request has been sent
     * through the {@link #getHttpClient()} so that the server
     * certificate is available.</p>
     *
     * @return an unmodifiable list of verification results
     * @throws AtiException if no server certificate has been captured
     *                      yet, or if a REQUIRED verification fails
     */
    public List<VerificationResult> verify() {
        X509Certificate serverCert =
            trustManager.getLastCapturedServerCert();
        if (serverCert == null) {
            throw new AtiException(
                "No server certificate captured yet. "
                    + "Send a request first.");
        }
        return connectionVerifier.postVerify(serverCert, preResult);
    }

    /**
     * Returns the HTTP client configured with the SSL context.
     *
     * @return the HTTP client
     */
    public HttpClient getHttpClient() {
        return httpClient;
    }

    /**
     * Returns the discovered agent descriptor.
     *
     * @return the agent descriptor
     */
    public AtiAgentDescriptor getDescriptor() {
        return descriptor;
    }
}
