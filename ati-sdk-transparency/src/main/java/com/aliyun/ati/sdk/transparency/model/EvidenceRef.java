package com.aliyun.ati.sdk.transparency.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Evidence reference section of a CNNIC TL response.
 *
 * <p>The evidence reference contains metadata about the evidence submission
 * that was used to create the transparency log entry, including a hash of
 * the evidence bytes for integrity verification.</p>
 *
 * <p>Example:</p>
 * <pre>{@code
 * {
 *     "evidenceId": "aliyun-tl-effae2b2-...",
 *     "submitterId": "aliyun",
 *     "evidenceType": "ALIYUN_SIGNED_SUBMISSION",
 *     "evidenceUri": "data:application/json;base64,...",
 *     "evidenceHash": "SHA-256:971452...",
 *     "hashAlgorithm": "SHA-256",
 *     "hashTarget": "EVIDENCE_BYTES",
 *     "contentType": "application/json",
 *     "evidenceSchemaVersion": "ATI-EVIDENCE-V1",
 *     "signatureRequired": false
 * }
 * }</pre>
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class EvidenceRef {

    @JsonProperty("evidenceId")
    private String evidenceId;

    @JsonProperty("submitterId")
    private String submitterId;

    @JsonProperty("evidenceType")
    private String evidenceType;

    @JsonProperty("evidenceUri")
    private String evidenceUri;

    @JsonProperty("evidenceHash")
    private String evidenceHash;

    @JsonProperty("hashAlgorithm")
    private String hashAlgorithm;

    @JsonProperty("hashTarget")
    private String hashTarget;

    @JsonProperty("contentType")
    private String contentType;

    @JsonProperty("evidenceSchemaVersion")
    private String evidenceSchemaVersion;

    @JsonProperty("signatureRequired")
    private Boolean signatureRequired;

    public EvidenceRef() {
    }

    public String getEvidenceId() {
        return evidenceId;
    }

    public void setEvidenceId(String evidenceId) {
        this.evidenceId = evidenceId;
    }

    public String getSubmitterId() {
        return submitterId;
    }

    public void setSubmitterId(String submitterId) {
        this.submitterId = submitterId;
    }

    public String getEvidenceType() {
        return evidenceType;
    }

    public void setEvidenceType(String evidenceType) {
        this.evidenceType = evidenceType;
    }

    public String getEvidenceUri() {
        return evidenceUri;
    }

    public void setEvidenceUri(String evidenceUri) {
        this.evidenceUri = evidenceUri;
    }

    public String getEvidenceHash() {
        return evidenceHash;
    }

    public void setEvidenceHash(String evidenceHash) {
        this.evidenceHash = evidenceHash;
    }

    public String getHashAlgorithm() {
        return hashAlgorithm;
    }

    public void setHashAlgorithm(String hashAlgorithm) {
        this.hashAlgorithm = hashAlgorithm;
    }

    public String getHashTarget() {
        return hashTarget;
    }

    public void setHashTarget(String hashTarget) {
        this.hashTarget = hashTarget;
    }

    public String getContentType() {
        return contentType;
    }

    public void setContentType(String contentType) {
        this.contentType = contentType;
    }

    public String getEvidenceSchemaVersion() {
        return evidenceSchemaVersion;
    }

    public void setEvidenceSchemaVersion(String evidenceSchemaVersion) {
        this.evidenceSchemaVersion = evidenceSchemaVersion;
    }

    public Boolean getSignatureRequired() {
        return signatureRequired;
    }

    public void setSignatureRequired(Boolean signatureRequired) {
        this.signatureRequired = signatureRequired;
    }

    @Override
    public String toString() {
        return "EvidenceRef{"
            + "evidenceId='" + evidenceId + '\''
            + ", evidenceType='" + evidenceType + '\''
            + ", evidenceHash='" + evidenceHash + '\''
            + '}';
    }
}
