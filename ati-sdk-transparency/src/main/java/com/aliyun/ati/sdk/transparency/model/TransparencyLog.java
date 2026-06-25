package com.aliyun.ati.sdk.transparency.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.Map;

/**
 * Transparency log entry for an agent.
 *
 * <p>This is the main response from the ATI transparency log API.
 * Use {@link #getParsedPayload()} to access the strongly-typed
 * {@link TransparencyLogAtiV1} payload.</p>
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class TransparencyLog {

    @JsonProperty("merkleProof")
    private MerkleProof merkleProof;

    @JsonProperty("payload")
    private Map<String, Object> payload;

    @JsonProperty("schemaVersion")
    private String schemaVersion;

    @JsonProperty("signature")
    private String signature;

    @JsonProperty("status")
    private String status;

    @JsonProperty("seal")
    private Seal seal;

    @JsonProperty("evidenceRef")
    private EvidenceRef evidenceRef;

    @JsonIgnore
    private TransparencyLogAtiV1 parsedPayload;

    public TransparencyLog() {
    }

    public MerkleProof getMerkleProof() {
        return merkleProof;
    }

    public void setMerkleProof(MerkleProof merkleProof) {
        this.merkleProof = merkleProof;
    }

    public Map<String, Object> getPayload() {
        return payload;
    }

    public void setPayload(Map<String, Object> payload) {
        this.payload = payload;
    }

    public String getSchemaVersion() {
        return schemaVersion;
    }

    public void setSchemaVersion(String schemaVersion) {
        this.schemaVersion = schemaVersion;
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public Seal getSeal() {
        return seal;
    }

    public void setSeal(Seal seal) {
        this.seal = seal;
    }

    public EvidenceRef getEvidenceRef() {
        return evidenceRef;
    }

    public void setEvidenceRef(EvidenceRef evidenceRef) {
        this.evidenceRef = evidenceRef;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public TransparencyLogAtiV1 getParsedPayload() {
        return parsedPayload;
    }

    public void setParsedPayload(TransparencyLogAtiV1 parsedPayload) {
        this.parsedPayload = parsedPayload;
    }

    /**
     * Convenience method to get the server certificate fingerprint.
     *
     * @return the server certificate fingerprint, or null if not available
     */
    public String getServerCertFingerprint() {
        if (parsedPayload != null && parsedPayload.getCertificates() != null) {
            return parsedPayload.getCertificates().getServerCertFingerprint();
        }
        return null;
    }

    /**
     * Convenience method to get the identity certificate fingerprint.
     *
     * @return the identity certificate fingerprint, or null if not available
     */
    public String getIdentityCertFingerprint() {
        if (parsedPayload != null && parsedPayload.getCertificates() != null) {
            return parsedPayload.getCertificates().getIdentityCertFingerprint();
        }
        return null;
    }

    /**
     * Convenience method to get the ATI name.
     *
     * @return the ATI name (e.g. "ati://v1.0.0.agent.example.com"), or null
     */
    public String getAtiName() {
        return parsedPayload != null ? parsedPayload.getAgentName() : null;
    }

    /**
     * Convenience method to get the agent host (FQDN).
     *
     * @return the agent host, or null if not available
     */
    public String getAgentHost() {
        return parsedPayload != null ? parsedPayload.getAgentHost() : null;
    }

    @Override
    public String toString() {
        return "TransparencyLog{"
            + "status='" + status + '\''
            + ", schemaVersion='" + schemaVersion + '\''
            + ", merkleProof=" + merkleProof
            + '}';
    }
}
