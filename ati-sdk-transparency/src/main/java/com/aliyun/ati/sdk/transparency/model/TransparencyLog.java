package com.aliyun.ati.sdk.transparency.model;

import com.fasterxml.jackson.annotation.JsonIgnore;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

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

    private static final ObjectMapper EVIDENCE_REF_MAPPER = new ObjectMapper()
        .configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

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

    private Map<String, Object> evidenceRef;

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

    /**
     * Typed view of known Evidence Ref fields. Extra TLog keys are kept on
     * {@link #getRawEvidenceRef()} for Seal JCS, not on this object.
     *
     * @return parsed Evidence Ref, or null
     */
    @JsonIgnore
    public EvidenceRef getEvidenceRef() {
        if (evidenceRef == null) {
            return null;
        }
        return EVIDENCE_REF_MAPPER.convertValue(evidenceRef, EvidenceRef.class);
    }

    /**
     * Original {@code evidenceRef} object as returned by the TL. Used for Seal
     * JCS so unknown keys are not dropped.
     *
     * @return raw evidenceRef map, or null
     */
    @JsonProperty("evidenceRef")
    public Map<String, Object> getRawEvidenceRef() {
        return evidenceRef;
    }

    @JsonIgnore
    @SuppressWarnings("unchecked")
    public void setEvidenceRef(EvidenceRef evidenceRef) {
        this.evidenceRef = evidenceRef == null
            ? null
            : EVIDENCE_REF_MAPPER.convertValue(evidenceRef, Map.class);
    }

    @JsonProperty("evidenceRef")
    public void setRawEvidenceRef(Map<String, Object> evidenceRef) {
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
     * Previous Server Cert Fingerprint from the Badge Entry, if any.
     *
     * @return the previous server certificate fingerprint, or null if not available
     */
    public String getPreviousServerCertFingerprint() {
        if (parsedPayload != null && parsedPayload.getCertificates() != null) {
            return parsedPayload.getCertificates().getPreviousServerCertFingerprint();
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
     * Previous Identity Cert Fingerprint from the Badge Entry, if any.
     *
     * @return the previous identity certificate fingerprint, or null if not available
     */
    public String getPreviousIdentityCertFingerprint() {
        if (parsedPayload != null && parsedPayload.getCertificates() != null) {
            return parsedPayload.getCertificates().getPreviousIdentityCertFingerprint();
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
     * Derived Identity Hostname from the Badge Entry.
     *
     * <p>{@code payload.agentSubHost} when non-blank (Shared Domain Mode);
     * otherwise {@code payload.agentHost} (Independent Domain Mode or legacy
     * entries without {@code agentSubHost}).</p>
     *
     * @return the Identity Hostname, or null if not available
     */
    public String getIdentityHost() {
        if (parsedPayload == null) {
            return null;
        }
        String subHost = parsedPayload.getAgentSubHost();
        if (subHost != null && !subHost.isBlank()) {
            return subHost;
        }
        return parsedPayload.getAgentHost();
    }

    /**
     * Access Hostname from {@code payload.agentHost} (CNNIC-locked wire field).
     *
     * @return the Access Hostname, or null if not available
     */
    public String getAccessHost() {
        return parsedPayload != null ? parsedPayload.getAgentHost() : null;
    }

    /**
     * Leftover alias of {@link #getIdentityHost()} — not {@code payload.agentHost}.
     *
     * @return the Identity Hostname, or null if not available
     */
    public String getAgentHost() {
        return getIdentityHost();
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
