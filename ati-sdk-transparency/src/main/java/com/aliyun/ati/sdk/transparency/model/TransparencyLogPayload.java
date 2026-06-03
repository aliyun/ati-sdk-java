package com.aliyun.ati.sdk.transparency.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public final class TransparencyLogPayload {

    private String logId;
    private String eventType;
    private String timestamp;
    private String agentName;
    private String agentHost;
    private String version;
    private String agentId;
    private String agentStatus;
    private Certificates certificates;

    private TransparencyLogPayload() {
    }

    public String getLogId() {
        return logId;
    }

    public String getEventType() {
        return eventType;
    }

    public String getTimestamp() {
        return timestamp;
    }

    public String getAgentName() {
        return agentName;
    }

    public String getAgentHost() {
        return agentHost;
    }

    public String getVersion() {
        return version;
    }

    public String getAgentId() {
        return agentId;
    }

    public String getAgentStatus() {
        return agentStatus;
    }

    public Certificates getCertificates() {
        return certificates;
    }
}
