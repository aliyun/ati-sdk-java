package com.aliyun.ati.sdk.discovery;

import java.net.URI;
import java.util.ArrayList;
import java.util.List;

/**
 * Details of a discovered ATI agent from DNS {@code _ati} TXT records.
 */
public final class AgentDetail {

    private String agentHost;
    private String accessHost;
    private String agentVersion;
    private List<AgentEndpoint> endpoints;

    public String getAgentHost() {
        return agentHost;
    }

    public void setAgentHost(String agentHost) {
        this.agentHost = agentHost;
    }

    public String getAccessHost() {
        return accessHost;
    }

    public void setAccessHost(String accessHost) {
        this.accessHost = accessHost;
    }

    public String getAgentVersion() {
        return agentVersion;
    }

    public void setAgentVersion(String agentVersion) {
        this.agentVersion = agentVersion;
    }

    public List<AgentEndpoint> getEndpoints() {
        return endpoints;
    }

    public void setEndpoints(List<AgentEndpoint> endpoints) {
        this.endpoints = endpoints;
    }

    /**
     * Creates {@link ConnectOptions}-friendly helpers from this discovery result.
     *
     * @return a snapshot with identity and access hostnames
     */
    public HostnamePair hostnamePair() {
        return new HostnamePair(agentHost, accessHost);
    }

    /**
     * Identity and Access hostnames from discovery.
     */
    public record HostnamePair(String identityHost, String accessHost) {
    }

    @Override
    public String toString() {
        return "AgentDetail{"
            + "agentHost='" + agentHost + '\''
            + ", accessHost='" + accessHost + '\''
            + ", agentVersion='" + agentVersion + '\''
            + ", endpoints=" + (endpoints != null ? endpoints.size() : 0)
            + '}';
    }

    static String extractAccessHost(List<AgentEndpoint> endpoints) {
        if (endpoints == null || endpoints.isEmpty()) {
            return null;
        }
        String agentUrl = endpoints.get(0).getAgentUrl();
        if (agentUrl == null || agentUrl.isBlank()) {
            return null;
        }
        return URI.create(agentUrl).getHost();
    }

    static List<AgentEndpoint> toEndpoints(List<AtiDiscoveryRecord> records) {
        List<AgentEndpoint> endpoints = new ArrayList<>();
        for (AtiDiscoveryRecord record : records) {
            AgentEndpoint endpoint = new AgentEndpoint();
            endpoint.setProtocol(DiscoveryProtocols.toEndpointProtocol(record.getProtocol()));
            endpoint.setAgentUrl(record.getAgentUrl());
            endpoint.setTransports(List.of());
            endpoints.add(endpoint);
        }
        return endpoints;
    }
}
