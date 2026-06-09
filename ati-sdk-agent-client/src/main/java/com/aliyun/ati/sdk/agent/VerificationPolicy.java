package com.aliyun.ati.sdk.agent;

/**
 * Defines the target verification level for ATI agent connections.
 *
 * <p>The SDK always attempts to reach the specified level. The actual
 * achieved level may be lower due to infrastructure unavailability
 * (e.g., DNSSEC INSECURE, TL unreachable). The caller inspects the
 * results from {@link AtiConnection#verify()} to decide whether
 * the achieved level is acceptable for their use case.
 */
public enum VerificationPolicy {
    BRONZE,
    SILVER,
    GOLD
}
