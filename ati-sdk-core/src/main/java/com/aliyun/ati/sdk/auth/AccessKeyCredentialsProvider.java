package com.aliyun.ati.sdk.auth;

public final class AccessKeyCredentialsProvider implements AtiCredentialsProvider {

    private final AtiCredentials credentials;

    public AccessKeyCredentialsProvider(String accessKeyId, String accessKeySecret) {
        this.credentials = AtiCredentials.ofAccessKey(accessKeyId, accessKeySecret);
    }

    @Override
    public AtiCredentials resolveCredentials() {
        return credentials;
    }
}
