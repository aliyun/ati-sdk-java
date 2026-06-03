package com.aliyun.ati.sdk.transparency.verification;

/**
 * Outcome status of a badge verification operation.
 */
public enum VerificationStatus {

    /** All checks passed. */
    VERIFIED,

    /** The agent ID was not found in the Transparency Log. */
    NOT_ATI_AGENT,

    /** The agent's registration record is invalid. */
    REGISTRATION_INVALID,

    /** The certificate fingerprint does not match the TL record. */
    FINGERPRINT_MISMATCH,

    /** The TL seal signature verification failed. */
    SEAL_INVALID,

    /** The Merkle inclusion proof verification failed. */
    MERKLE_PROOF_INVALID,

    /** The agent has been revoked or is not in ACTIVE status. */
    AGENT_REVOKED,

    /** An error occurred while looking up the agent or its keys. */
    LOOKUP_FAILED
}
