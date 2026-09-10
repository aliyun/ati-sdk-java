package com.aliyun.ati.sdk.transparency.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * ATI-TL-V1 schema for CNNIC Transparency Log entries.
 *
 * <p>This is a flat payload structure used by the ATI transparency log,
 * distinct from the GoDaddy ANS V0/V1 nested schemas.</p>
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class TransparencyLogAtiV1 {

    @JsonProperty("logId")
    private String logId;

    @JsonProperty("eventType")
    private String eventType;

    @JsonProperty("timestamp")
    private String timestamp;

    @JsonProperty("agentName")
    private String agentName;

    @JsonProperty("agentHost")
    private String agentHost;

    @JsonProperty("agentSubHost")
    private String agentSubHost;

    @JsonProperty("version")
    private String version;

    @JsonProperty("agentId")
    private String agentId;

    @JsonProperty("agentStatus")
    private String agentStatus;

    @JsonProperty("certificates")
    private Certificates certificates;

    public String getLogId() { return logId; }
    public void setLogId(String logId) { this.logId = logId; }

    public String getEventType() { return eventType; }
    public void setEventType(String eventType) { this.eventType = eventType; }

    public String getTimestamp() { return timestamp; }
    public void setTimestamp(String timestamp) { this.timestamp = timestamp; }

    public String getAgentName() { return agentName; }
    public void setAgentName(String agentName) { this.agentName = agentName; }

    public String getAgentHost() { return agentHost; }
    public void setAgentHost(String agentHost) { this.agentHost = agentHost; }

    public String getAgentSubHost() { return agentSubHost; }
    public void setAgentSubHost(String agentSubHost) { this.agentSubHost = agentSubHost; }

    public String getVersion() { return version; }
    public void setVersion(String version) { this.version = version; }

    public String getAgentId() { return agentId; }
    public void setAgentId(String agentId) { this.agentId = agentId; }

    public String getAgentStatus() { return agentStatus; }
    public void setAgentStatus(String agentStatus) { this.agentStatus = agentStatus; }

    public Certificates getCertificates() { return certificates; }
    public void setCertificates(Certificates certificates) { this.certificates = certificates; }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class Certificates {

        @JsonProperty("serverCertFingerprint")
        private String serverCertFingerprint;

        @JsonProperty("previousServerCertFingerprint")
        private String previousServerCertFingerprint;

        @JsonProperty("identityCertFingerprint")
        private String identityCertFingerprint;

        @JsonProperty("previousIdentityCertFingerprint")
        private String previousIdentityCertFingerprint;

        public String getServerCertFingerprint() { return serverCertFingerprint; }
        public void setServerCertFingerprint(String serverCertFingerprint) { this.serverCertFingerprint = serverCertFingerprint; }

        public String getPreviousServerCertFingerprint() { return previousServerCertFingerprint; }
        public void setPreviousServerCertFingerprint(String previousServerCertFingerprint) { this.previousServerCertFingerprint = previousServerCertFingerprint; }

        public String getIdentityCertFingerprint() { return identityCertFingerprint; }
        public void setIdentityCertFingerprint(String identityCertFingerprint) { this.identityCertFingerprint = identityCertFingerprint; }

        public String getPreviousIdentityCertFingerprint() { return previousIdentityCertFingerprint; }
        public void setPreviousIdentityCertFingerprint(String previousIdentityCertFingerprint) { this.previousIdentityCertFingerprint = previousIdentityCertFingerprint; }

        @Override
        public String toString() {
            return "Certificates{"
                + "serverCertFingerprint='" + serverCertFingerprint + '\''
                + ", identityCertFingerprint='" + identityCertFingerprint + '\''
                + '}';
        }
    }

    @Override
    public String toString() {
        return "TransparencyLogAtiV1{"
            + "agentName='" + agentName + '\''
            + ", agentHost='" + agentHost + '\''
            + ", agentSubHost='" + agentSubHost + '\''
            + ", version='" + version + '\''
            + ", agentStatus='" + agentStatus + '\''
            + ", certificates=" + certificates
            + '}';
    }
}
