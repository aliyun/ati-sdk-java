package com.aliyun.ati.sdk.agent.http;

import com.aliyun.ati.sdk.agent.verification.ConnectionVerifier;

import java.util.Objects;

/**
 * Result of creating a verified HTTP client setup.
 *
 * <p>This record contains all the components needed for agent communication
 * with verification outside the TLS handshake:</p>
 * <ul>
 *   <li><b>verifier</b>: ConnectionVerifier for pre/post verification</li>
 *   <li><b>atiHttpClient</b>: Wrapper that orchestrates verification</li>
 * </ul>
 *  @param verifier the connection verifier for DANE/Badge verification
 *
 * @param atiHttpClient the wrapper client that performs verification
 */
public record VerifiedClientResult(
        ConnectionVerifier verifier,
        AtiHttpClient atiHttpClient
) {

    public VerifiedClientResult {
        Objects.requireNonNull(verifier, "ConnectionVerifier cannot be null");
        Objects.requireNonNull(atiHttpClient, "AtiHttpClient cannot be null");
    }
}
