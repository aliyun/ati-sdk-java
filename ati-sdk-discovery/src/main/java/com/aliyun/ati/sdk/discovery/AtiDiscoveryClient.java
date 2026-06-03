package com.aliyun.ati.sdk.discovery;

/**
 * Client for discovering ATI agents by their {@link AtiName}.
 *
 * <p>Implementations resolve an ATI name to an {@link AtiAgentDescriptor} containing
 * the agent's host, version, badge URL, and agent ID.
 */
public interface AtiDiscoveryClient {

    /**
     * Discovers an agent by its ATI name.
     *
     * @param name the ATI name to resolve
     * @return the agent descriptor
     * @throws NullPointerException if name is null
     */
    AtiAgentDescriptor discover(AtiName name);
}
