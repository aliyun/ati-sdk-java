package com.aliyun.ati.sdk.discovery;

import java.util.Objects;

/**
 * Immutable value object describing a discovered Agent.
 *
 * <p>Contains the agent host, version, and optional badge URL and agent ID
 * obtained from DNS discovery records.
 */
public final class AtiAgentDescriptor {

    private final String agentHost;
    private final String version;
    private final String badgeUrl;
    private final String agentId;

    /**
     * Creates a new agent descriptor.
     *
     * @param agentHost the agent host name (required)
     * @param version   the agent version (required)
     * @param badgeUrl  the badge URL from the TL (nullable)
     * @param agentId   the agent identifier (nullable)
     */
    public AtiAgentDescriptor(String agentHost, String version, String badgeUrl, String agentId) {
        this.agentHost = Objects.requireNonNull(agentHost, "agentHost must not be null");
        this.version = Objects.requireNonNull(version, "version must not be null");
        this.badgeUrl = badgeUrl;
        this.agentId = agentId;
    }

    public String getAgentHost() {
        return agentHost;
    }

    public String getVersion() {
        return version;
    }

    public String getBadgeUrl() {
        return badgeUrl;
    }

    public String getAgentId() {
        return agentId;
    }

    @Override
    public String toString() {
        return "AtiAgentDescriptor{host=" + agentHost + ", version=" + version + ", agentId=" + agentId + "}";
    }
}
