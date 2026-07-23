package com.aliyun.ati.sdk.agent;

/**
 * Progressive verification policy for agent connections, aligned with ATI Console trust levels.
 *
 * <ul>
 *   <li>{@link #NONE} — L0 无认证: no TLS certificate validation, no ATI verification (dev/test only)</li>
 *   <li>{@link #BASIC} — L1 基础认证: standard TLS PKI verification</li>
 *   <li>{@link #ENHANCED} — L2 增强认证: Basic + Badge (transparency log seal, Merkle proof, fingerprint)</li>
 *   <li>{@link #ADVANCED} — L3 高级认证: Enhanced + DANE (requires DNSSEC infrastructure)</li>
 * </ul>
 *
 * <h2>Usage</h2>
 * <pre>{@code
 * ConnectOptions.builder()
 *     .verificationPolicy(VerificationPolicy.ENHANCED)
 *     .build();
 * }</pre>
 *
 * @see ConnectOptions.Builder#verificationPolicy(VerificationPolicy)
 */
public enum VerificationPolicy {

    /**
     * No authentication — skip TLS certificate validation and all ATI verification.
     *
     * <p>For development and testing only. Do not use in production.</p>
     */
    NONE,

    /**
     * Basic authentication — standard PKI trust via the JVM default trust store (or IDCA on servers).
     */
    BASIC,

    /**
     * Enhanced authentication — Basic + Badge verification via the ATI transparency log.
     *
     * <p>Recommended default for production use.</p>
     */
    ENHANCED,

    /**
     * Advanced authentication — Enhanced + DANE verification (DNSSEC-secured TLSA records).
     */
    ADVANCED;

    /**
     * Returns the ATI Console display label (e.g. {@code "L2 增强认证"}).
     */
    public String displayName() {
        return switch (this) {
            case NONE -> "L0 无认证";
            case BASIC -> "L1 基础认证";
            case ENHANCED -> "L2 增强认证";
            case ADVANCED -> "L3 高级认证";
        };
    }

    /**
     * Parses a policy from a configuration string (case-insensitive).
     *
     * @param value the policy name ({@code NONE}, {@code BASIC}, {@code ENHANCED}, or {@code ADVANCED})
     * @return the matching policy
     * @throws IllegalArgumentException if the value is not recognized
     */
    public static VerificationPolicy fromString(String value) {
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("Verification policy cannot be null or blank");
        }
        return valueOf(value.trim().toUpperCase());
    }

    /**
     * Returns true if standard TLS PKI validation is enabled.
     */
    public boolean hasPkiVerification() {
        return this != NONE;
    }

    /**
     * Returns true if any ATI verification beyond PKI is enabled (Badge or DANE).
     */
    public boolean hasAnyVerification() {
        return this == ENHANCED || this == ADVANCED;
    }

    /**
     * Returns true if badge verification is enabled.
     */
    public boolean hasBadgeVerification() {
        return this == ENHANCED || this == ADVANCED;
    }

    /**
     * Returns true if DANE verification is enabled.
     */
    public boolean hasDaneVerification() {
        return this == ADVANCED;
    }

    /**
     * Returns true if this policy requires an IDCA trust anchor on the server.
     */
    public boolean requiresIdcaTrust() {
        return this == ENHANCED || this == ADVANCED;
    }
}
