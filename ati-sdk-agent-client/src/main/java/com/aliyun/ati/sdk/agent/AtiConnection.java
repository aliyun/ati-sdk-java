package com.aliyun.ati.sdk.agent;

import java.net.http.HttpClient;
import java.util.Collections;
import java.util.List;
import java.util.Objects;

import com.aliyun.ati.sdk.agent.verification.VerificationResult;
import com.aliyun.ati.sdk.discovery.AtiAgentDescriptor;

/**
 * Holds the verified connection to an ATI agent.
 *
 * <p>Contains the {@link HttpClient} configured with the verified SSL context,
 * the {@link AtiAgentDescriptor} from discovery, and the verification results
 * from DANE and/or Badge verification.
 *
 * <p>The verification results list is unmodifiable.
 */
public final class AtiConnection {

    private final HttpClient httpClient;
    private final AtiAgentDescriptor descriptor;
    private final List<VerificationResult> verificationResults;

    /**
     * Creates a new ATI connection.
     *
     * @param httpClient          the HTTP client with verified SSL context
     * @param descriptor          the discovered agent descriptor
     * @param verificationResults the verification results
     */
    public AtiConnection(HttpClient httpClient,
                         AtiAgentDescriptor descriptor,
                         List<VerificationResult> verificationResults) {
        this.httpClient = Objects.requireNonNull(httpClient,
            "httpClient must not be null");
        this.descriptor = Objects.requireNonNull(descriptor,
            "descriptor must not be null");
        this.verificationResults = Collections.unmodifiableList(
            Objects.requireNonNull(verificationResults,
                "verificationResults must not be null"));
    }

    /**
     * Returns the HTTP client configured with the verified SSL context.
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

    /**
     * Returns an unmodifiable list of verification results.
     *
     * @return the verification results
     */
    public List<VerificationResult> getVerificationResults() {
        return verificationResults;
    }
}
