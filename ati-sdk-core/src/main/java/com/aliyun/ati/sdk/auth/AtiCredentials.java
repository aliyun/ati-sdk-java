package com.aliyun.ati.sdk.auth;

public final class AtiCredentials {

    private final CredentialType type;
    private final String accessToken;
    private final String accessKeyId;
    private final String accessKeySecret;

    private AtiCredentials(CredentialType type, String accessToken,
                           String accessKeyId, String accessKeySecret) {
        this.type = type;
        this.accessToken = accessToken;
        this.accessKeyId = accessKeyId;
        this.accessKeySecret = accessKeySecret;
    }

    public static AtiCredentials ofAccessToken(String token) {
        if (token == null || token.isBlank()) {
            throw new IllegalArgumentException("Access token cannot be null or blank");
        }
        return new AtiCredentials(CredentialType.ACCESS_TOKEN, token, null, null);
    }

    public static AtiCredentials ofAccessKey(String accessKeyId, String accessKeySecret) {
        if (accessKeyId == null || accessKeyId.isBlank()) {
            throw new IllegalArgumentException("Access key ID cannot be null or blank");
        }
        if (accessKeySecret == null || accessKeySecret.isBlank()) {
            throw new IllegalArgumentException("Access key secret cannot be null or blank");
        }
        return new AtiCredentials(CredentialType.ACCESS_KEY, null, accessKeyId, accessKeySecret);
    }

    public CredentialType getType() {
        return type;
    }

    public String getAccessToken() {
        return accessToken;
    }

    public String getAccessKeyId() {
        return accessKeyId;
    }

    public String getAccessKeySecret() {
        return accessKeySecret;
    }

    public String toAuthorizationHeader() {
        return switch (type) {
            case ACCESS_TOKEN -> "Bearer " + accessToken;
            case ACCESS_KEY -> "AccessKey " + accessKeyId + ":" + accessKeySecret;
        };
    }

    public enum CredentialType {
        ACCESS_TOKEN,
        ACCESS_KEY
    }
}
