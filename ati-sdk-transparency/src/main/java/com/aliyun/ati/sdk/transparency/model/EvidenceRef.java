package com.aliyun.ati.sdk.transparency.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public final class EvidenceRef {

    private String evidenceId;
    private String submitterId;
    private String evidenceType;
    private String evidenceUri;
    private String evidenceHash;
    private String hashAlgorithm;
    private String hashTarget;
    private String contentType;
    private String evidenceSchemaVersion;
    private Boolean signatureRequired;

    private EvidenceRef() {
    }

    public String getEvidenceId() {
        return evidenceId;
    }

    public String getSubmitterId() {
        return submitterId;
    }

    public String getEvidenceType() {
        return evidenceType;
    }

    public String getEvidenceUri() {
        return evidenceUri;
    }

    public String getEvidenceHash() {
        return evidenceHash;
    }

    public String getHashAlgorithm() {
        return hashAlgorithm;
    }

    public String getHashTarget() {
        return hashTarget;
    }

    public String getContentType() {
        return contentType;
    }

    public String getEvidenceSchemaVersion() {
        return evidenceSchemaVersion;
    }

    public Boolean isSignatureRequired() {
        return signatureRequired;
    }
}
