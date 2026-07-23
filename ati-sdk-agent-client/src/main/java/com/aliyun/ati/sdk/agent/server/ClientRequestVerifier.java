package com.aliyun.ati.sdk.agent.server;

import com.aliyun.ati.sdk.agent.VerificationPolicy;

import java.security.cert.X509Certificate;

/**
 * Server-side verifier for incoming client requests.
 *
 * <p>This interface provides a high-level API for MCP servers (and other server
 * implementations) to verify that incoming client requests are from legitimate
 * ATI-registered agents.</p>
 *
 * <p>Verification proceeds according to the specified {@link VerificationPolicy}:</p>
 * <ol>
 *   <li><b>NONE</b> — Skip all client verification (dev/test only)</li>
 *   <li><b>BASIC</b> — Extract agent identity from the certificate URI SAN only</li>
 *   <li><b>ENHANCED</b> — Basic + Badge verification via DNS {@code _ati-badge}
 *       record and transparency log (seal signature, Merkle proof, fingerprint match)</li>
 *   <li><b>ADVANCED</b> — Enhanced + DANE verification via DNSSEC-secured
 *       {@code _ati-identity._tls} TLSA record</li>
 * </ol>
 *
 * <h2>Usage Example</h2>
 * <pre>{@code
 * ClientRequestVerifier verifier = DefaultClientRequestVerifier.builder()
 *     .badgeVerificationService(badgeService)
 *     .build();
 *
 * // In request handler
 * X509Certificate clientCert = (X509Certificate) sslSession.getPeerCertificates()[0];
 *
 * ClientRequestVerificationResult result = verifier.verify(
 *     clientCert, VerificationPolicy.ENHANCED);
 *
 * if (!result.verified()) {
 *     return Response.status(403)
 *         .entity("Client verification failed: " + result.errors())
 *         .build();
 * }
 *
 * // Proceed with verified agent identity
 * String agentHost = result.agentHost();
 * }</pre>
 *
 * @see DefaultClientRequestVerifier
 * @see ClientRequestVerificationResult
 */
public interface ClientRequestVerifier {

    /**
     * Verifies an incoming client request.
     *
     * <p>This method extracts the agent identity from the client's Identity Certificate
     * URI SAN and verifies it according to the specified policy. Badge verification
     * uses DNS {@code _ati-badge} records and the transparency log. DANE verification
     * uses DNSSEC-secured {@code _ati-identity._tls} TLSA records.</p>
     *
     * @param clientCert the client's X.509 Identity Certificate from mTLS handshake
     * @param policy the verification policy to apply
     * @return the verification result (never null)
     * @throws NullPointerException if any parameter is null
     */
    ClientRequestVerificationResult verify(
        X509Certificate clientCert,
        VerificationPolicy policy
    );

    /**
     * Verifies an incoming client request using the default BASIC policy.
     *
     * <p>This is the simplest verification level: it extracts the agent identity
     * from the certificate URI SAN but performs no Badge or DANE checks.</p>
     *
     * @param clientCert the client's X.509 Identity Certificate from mTLS handshake
     * @return the verification result (never null)
     * @throws NullPointerException if clientCert is null
     */
    default ClientRequestVerificationResult verify(X509Certificate clientCert) {
        return verify(clientCert, VerificationPolicy.BASIC);
    }
}
