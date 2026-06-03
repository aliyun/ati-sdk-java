package com.aliyun.ati.sdk.transparency.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public final class Certificates {

    private String serverCertFingerprint;
    private String identityCertFingerprint;

    private Certificates() {
    }

    public String getServerCertFingerprint() {
        return serverCertFingerprint;
    }

    public String getIdentityCertFingerprint() {
        return identityCertFingerprint;
    }
}
