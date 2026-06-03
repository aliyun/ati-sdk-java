package com.aliyun.ati.sdk.transparency.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public final class TransparencyLogResponse {

    private String status;
    private String schemaVersion;
    private TransparencyLogPayload payload;
    private EvidenceRef evidenceRef;
    private Seal seal;
    private MerkleProof merkleProof;

    private TransparencyLogResponse() {
    }

    public String getStatus() {
        return status;
    }

    public String getSchemaVersion() {
        return schemaVersion;
    }

    public TransparencyLogPayload getPayload() {
        return payload;
    }

    public EvidenceRef getEvidenceRef() {
        return evidenceRef;
    }

    public Seal getSeal() {
        return seal;
    }

    public MerkleProof getMerkleProof() {
        return merkleProof;
    }
}
