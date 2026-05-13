package com.aliyun.ati.sdk.auth;

public final class AccessTokenCredentialsProvider implements AtiCredentialsProvider {

    private final AtiCredentials credentials;

    public AccessTokenCredentialsProvider(String accessToken) {
        this.credentials = AtiCredentials.ofAccessToken(accessToken);
    }

    @Override
    public AtiCredentials resolveCredentials() {
        return credentials;
    }
}
