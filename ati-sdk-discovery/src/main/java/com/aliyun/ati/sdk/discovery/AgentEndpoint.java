package com.aliyun.ati.sdk.discovery;

import java.util.List;

/**
 * An endpoint for an ATI agent, describing how to connect to it.
 *
 * <p>Each endpoint specifies a protocol, agent URL, metadata URL,
 * and supported transports.</p>
 */
public final class AgentEndpoint {

    private String protocol;
    private String agentUrl;
    private String metadataUrl;
    private List<String> transports;

    public String getProtocol() {
        return protocol;
    }

    public void setProtocol(String protocol) {
        this.protocol = protocol;
    }

    public String getAgentUrl() {
        return agentUrl;
    }

    public void setAgentUrl(String agentUrl) {
        this.agentUrl = agentUrl;
    }

    public String getMetadataUrl() {
        return metadataUrl;
    }

    public void setMetadataUrl(String metadataUrl) {
        this.metadataUrl = metadataUrl;
    }

    public List<String> getTransports() {
        return transports;
    }

    public void setTransports(List<String> transports) {
        this.transports = transports;
    }

    @Override
    public String toString() {
        return "AgentEndpoint{"
            + "protocol='" + protocol + '\''
            + ", agentUrl='" + agentUrl + '\''
            + '}';
    }
}
