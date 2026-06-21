package com.aliyun.ati.sdk.model.generated;

/**
 * Lifecycle status of an ATI-registered agent.
 *
 * <p>Mirrors the registry state machine:
 * PENDING -> PENDING_DNS -> ACTIVE -> DEPRECATED -> REVOKED</p>
 */
public enum AgentLifecycleStatus {
    /** Agent registration is pending initial setup. */
    PENDING,
    /** Agent is pending DNS record verification. */
    PENDING_DNS,
    /** Agent is actively registered and operational. */
    ACTIVE,
    /** Agent registration is deprecated but still valid. */
    DEPRECATED,
    /** Agent registration has been revoked. */
    REVOKED
}
