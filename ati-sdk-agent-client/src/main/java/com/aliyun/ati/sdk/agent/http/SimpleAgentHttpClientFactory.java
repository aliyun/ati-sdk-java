package com.aliyun.ati.sdk.agent.http;

import com.aliyun.ati.sdk.agent.ConnectOptions;
import com.aliyun.ati.sdk.agent.VerificationPolicy;
import com.aliyun.ati.sdk.agent.exception.AgentConnectionException;

import java.net.http.HttpClient;
import java.time.Duration;

/**
 * Simple implementation of {@link AgentHttpClientFactory} using JVM defaults.
 *
 * <p>This factory creates HttpClient instances with the JVM's default SSL
 * configuration. It does not support DANE or Badge verification.</p>
 *
 * <p>Primary use cases:</p>
 * <ul>
 *   <li>Testing with mock servers</li>
 *   <li>Connecting to agents that don't require ATI verification</li>
 *   <li>Development environments with self-signed certificates in trust store</li>
 * </ul>
 *
 * <p><strong>Note:</strong> This factory ignores the verification policy in
 * ConnectOptions. For production use with proper verification, use
 * {@link DefaultAgentHttpClientFactory} instead.</p>
 */
public class SimpleAgentHttpClientFactory implements AgentHttpClientFactory {

    @Override
    public HttpClient create(String hostname, ConnectOptions options, Duration connectTimeout)
            throws AgentConnectionException {
        return createVerified(hostname, options, connectTimeout).atiHttpClient().getDelegate();
    }

    @Override
    public VerifiedClientResult createVerified(String hostname, ConnectOptions options, Duration connectTimeout)
            throws AgentConnectionException {
        try {
            HttpClient httpClient = HttpClient.newBuilder()
                .connectTimeout(connectTimeout)
                .build();

            // Create verifying client with BASIC policy (no verification)
            AtiHttpClient verifyingClient = AtiHttpClient.builder()
                .delegate(httpClient)
                .connectionVerifier(NoOpConnectionVerifier.INSTANCE)
                .verificationPolicy(VerificationPolicy.BASIC)
                .build();

            return new VerifiedClientResult(NoOpConnectionVerifier.INSTANCE, verifyingClient);

        } catch (Exception e) {
            throw new AgentConnectionException(
                "Failed to create HTTP client: " + e.getMessage(), e, hostname);
        }
    }
}