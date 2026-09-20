package com.aliyun.ati.sdk.transparency.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * Seal section of a CNNIC TL response.
 *
 * <p>The seal contains a digital signature over the canonicalized content
 * (status, schemaVersion, payload, evidenceRef) using RFC 8785 JCS
 * canonicalization and SHA-256withRSA signature algorithm.</p>
 *
 * <p>Example:</p>
 * <pre>{@code
 * {
 *     "canonicalization": "RFC8785-JCS",
 *     "digestAlgorithm": "SHA-256",
 *     "signatureAlgorithm": "SHA-256withRSA",
 *     "signatureEncoding": "DER_BASE64",
 *     "keyId": "ati-tl-rsa-v1",
 *     "signature": "MEQCI...",
 *     "publicKey": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----",
 *     "certificate": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----"
 * }
 * }</pre>
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class Seal {

    @JsonProperty("canonicalization")
    private String canonicalization;

    @JsonProperty("digestAlgorithm")
    private String digestAlgorithm;

    @JsonProperty("signatureAlgorithm")
    private String signatureAlgorithm;

    @JsonProperty("signatureEncoding")
    private String signatureEncoding;

    @JsonProperty("keyId")
    private String keyId;

    @JsonProperty("signature")
    private String signature;

    @JsonProperty("publicKey")
    private String publicKey;

    /**
     * PEM-encoded Seal Certificate (leaf) attached by CNNIC to each Seal.
     *
     * <p>The certificate's public key verifies {@link #signature}, and the certificate is
     * PKIX path-validated to the SDK's built-in Seal CA Chain. See ADR 0011. May be a leaf-only
     * PEM or a leaf + intermediate bundle; the leaf is the first certificate.</p>
     */
    @JsonProperty("certificate")
    private String certificate;

    public Seal() {
    }

    public String getCanonicalization() {
        return canonicalization;
    }

    public void setCanonicalization(String canonicalization) {
        this.canonicalization = canonicalization;
    }

    public String getDigestAlgorithm() {
        return digestAlgorithm;
    }

    public void setDigestAlgorithm(String digestAlgorithm) {
        this.digestAlgorithm = digestAlgorithm;
    }

    public String getSignatureAlgorithm() {
        return signatureAlgorithm;
    }

    public void setSignatureAlgorithm(String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    public String getSignatureEncoding() {
        return signatureEncoding;
    }

    public void setSignatureEncoding(String signatureEncoding) {
        this.signatureEncoding = signatureEncoding;
    }

    public String getKeyId() {
        return keyId;
    }

    public void setKeyId(String keyId) {
        this.keyId = keyId;
    }

    public String getSignature() {
        return signature;
    }

    public void setSignature(String signature) {
        this.signature = signature;
    }

    public String getPublicKey() {
        return publicKey;
    }

    public void setPublicKey(String publicKey) {
        this.publicKey = publicKey;
    }

    public String getCertificate() {
        return certificate;
    }

    public void setCertificate(String certificate) {
        this.certificate = certificate;
    }

    @Override
    public String toString() {
        return "Seal{"
            + "canonicalization='" + canonicalization + '\''
            + ", signatureAlgorithm='" + signatureAlgorithm + '\''
            + ", keyId='" + keyId + '\''
            + '}';
    }
}
