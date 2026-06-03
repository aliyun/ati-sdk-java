package com.aliyun.ati.sdk.transparency.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public final class EvidenceRef {

    private String evidenceId;
    private String submitterId;
    private String evidenceType;
    private String evidenceUri;
    private String evidenceHash;

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
}
