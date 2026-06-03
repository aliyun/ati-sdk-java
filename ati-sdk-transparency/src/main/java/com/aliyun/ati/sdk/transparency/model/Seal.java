package com.aliyun.ati.sdk.transparency.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public final class Seal {

    private String canonicalization;
    private String digestAlgorithm;
    private String signatureAlgorithm;
    private String signatureEncoding;
    private String keyId;
    private String signature;
    private String publicKey;

    private Seal() {
    }

    public String getCanonicalization() {
        return canonicalization;
    }

    public String getDigestAlgorithm() {
        return digestAlgorithm;
    }

    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public String getSignatureEncoding() {
        return signatureEncoding;
    }

    public String getKeyId() {
        return keyId;
    }

    public String getSignature() {
        return signature;
    }

    public String getPublicKey() {
        return publicKey;
    }
}
