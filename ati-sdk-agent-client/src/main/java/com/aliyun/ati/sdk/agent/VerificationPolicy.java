package com.aliyun.ati.sdk.agent;

/**
 * Progressive verification policy for agent connections.
 *
 * <p>Each level includes all verifications from the previous level:</p>
 * <ul>
 *   <li>{@link #PKI_ONLY} - Standard TLS PKI verification only</li>
 *   <li>{@link #BADGE_REQUIRED} - PKI + Badge (transparency log seal, Merkle proof, fingerprint)</li>
 *   <li>{@link #DANE_AND_BADGE} - PKI + Badge + DANE (requires DNSSEC infrastructure)</li>
 * </ul>
 *
 * <h2>Usage</h2>
 * <pre>{@code
 * // Badge verification (recommended default)
 * ConnectOptions.builder()
 *     .verificationPolicy(VerificationPolicy.BADGE_REQUIRED)
 *     .build();
 *
 * // Maximum verification with DANE
 * ConnectOptions.builder()
 *     .verificationPolicy(VerificationPolicy.DANE_AND_BADGE)
 *     .build();
 * }</pre>
 *
 * @see ConnectOptions.Builder#verificationPolicy(VerificationPolicy)
 */
public enum VerificationPolicy {

    /**
     * Standard PKI trust only - no additional verification.
     *
     * <p>Uses the JVM's default trust store to validate certificates against
     * well-known Certificate Authorities. This is the minimum security level.</p>
     */
    PKI_ONLY,

    /**
     * PKI + Badge verification via ATI transparency log.
     *
     * <p>Verifies that the server is a registered ATI agent by checking the
     * transparency log (proof of registration with Merkle proof and certificate
     * fingerprint matching). This is the recommended default for most use cases.</p>
     */
    BADGE_REQUIRED,

    /**
     * PKI + Badge + DANE verification.
     *
     * <p>Combines badge verification with DNS-based Authentication of Named Entities
     * (DNSSEC-secured TLSA records). Requires both DNSSEC infrastructure and ATI
     * registration. Use this for maximum assurance.</p>
     */
    DANE_AND_BADGE;

    /**
     * Returns true if any verification beyond PKI is enabled.
     *
     * @return true if this policy requires Badge or DANE verification
     */
    public boolean hasAnyVerification() {
        return this != PKI_ONLY;
    }

    /**
     * Returns true if badge verification is enabled.
     *
     * @return true if this policy is BADGE_REQUIRED or higher
     */
    public boolean hasBadgeVerification() {
        return this.ordinal() >= BADGE_REQUIRED.ordinal();
    }

    /**
     * Returns true if DANE verification is enabled.
     *
     * @return true if this policy is DANE_AND_BADGE
     */
    public boolean hasDaneVerification() {
        return this == DANE_AND_BADGE;
    }
}
