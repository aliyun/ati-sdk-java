package com.aliyun.ati.sdk.model.generated;

import java.util.ArrayList;
import java.util.List;

/**
 * Details of an ATI-registered agent.
 *
 * <p>Contains the agent's registration information including host, version,
 * lifecycle status, and available endpoints.</p>
 */
public class AgentDetails {

    private String agentHost;
    private String atiName;
    private String version;
    private AgentLifecycleStatus agentStatus;
    private List<AgentEndpoint> endpoints = new ArrayList<>();

    /**
     * Returns the agent's hostname.
     *
     * @return the agent host
     */
    public String getAgentHost() {
        return agentHost;
    }

    /**
     * Sets the agent's hostname.
     *
     * @param agentHost the agent host
     */
    public void setAgentHost(String agentHost) {
        this.agentHost = agentHost;
    }

    /**
     * Returns the ATI name (e.g., "ati://v1.0.0.agent.example.com").
     *
     * @return the ATI name
     */
    public String getAtiName() {
        return atiName;
    }

    /**
     * Sets the ATI name.
     *
     * @param atiName the ATI name
     */
    public void setAtiName(String atiName) {
        this.atiName = atiName;
    }

    /**
     * Returns the agent version.
     *
     * @return the version
     */
    public String getVersion() {
        return version;
    }

    /**
     * Sets the agent version.
     *
     * @param version the version
     */
    public void setVersion(String version) {
        this.version = version;
    }

    /**
     * Returns the agent's lifecycle status.
     *
     * @return the lifecycle status
     */
    public AgentLifecycleStatus getAgentStatus() {
        return agentStatus;
    }

    /**
     * Sets the agent's lifecycle status.
     *
     * @param agentStatus the lifecycle status
     */
    public void setAgentStatus(AgentLifecycleStatus agentStatus) {
        this.agentStatus = agentStatus;
    }

    /**
     * Returns the agent's endpoints.
     *
     * @return list of endpoints
     */
    public List<AgentEndpoint> getEndpoints() {
        return endpoints;
    }

    /**
     * Sets the agent's endpoints.
     *
     * @param endpoints list of endpoints
     */
    public void setEndpoints(List<AgentEndpoint> endpoints) {
        this.endpoints = endpoints != null ? endpoints : new ArrayList<>();
    }
}
