package com.aliyun.ati.sdk.discovery;

import java.util.List;

/**
 * Details of a discovered ATI agent.
 *
 * <p>Returned by {@link AtiDiscoveryClient#discover(String, String)} when
 * an agent is found in the registry via Alibaba Cloud OpenAPI.</p>
 */
public final class AgentDetail {

    private String agentId;
    private String agentDisplayName;
    private String agentHost;
    private String agentVersion;
    private String agentDescription;
    private String status;
    private String trustLevel;
    private List<AgentEndpoint> endpoints;

    public String getAgentId() {
        return agentId;
    }

    public void setAgentId(String agentId) {
        this.agentId = agentId;
    }

    public String getAgentDisplayName() {
        return agentDisplayName;
    }

    public void setAgentDisplayName(String agentDisplayName) {
        this.agentDisplayName = agentDisplayName;
    }

    public String getAgentHost() {
        return agentHost;
    }

    public void setAgentHost(String agentHost) {
        this.agentHost = agentHost;
    }

    public String getAgentVersion() {
        return agentVersion;
    }

    public void setAgentVersion(String agentVersion) {
        this.agentVersion = agentVersion;
    }

    public String getAgentDescription() {
        return agentDescription;
    }

    public void setAgentDescription(String agentDescription) {
        this.agentDescription = agentDescription;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getTrustLevel() {
        return trustLevel;
    }

    public void setTrustLevel(String trustLevel) {
        this.trustLevel = trustLevel;
    }

    public List<AgentEndpoint> getEndpoints() {
        return endpoints;
    }

    public void setEndpoints(List<AgentEndpoint> endpoints) {
        this.endpoints = endpoints;
    }

    @Override
    public String toString() {
        return "AgentDetail{"
            + "agentId='" + agentId + '\''
            + ", agentHost='" + agentHost + '\''
            + ", agentVersion='" + agentVersion + '\''
            + ", status='" + status + '\''
            + '}';
    }
}
