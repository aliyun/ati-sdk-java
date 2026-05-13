package com.aliyun.ati.sdk.auth;

import com.aliyun.ati.sdk.exception.AtiAuthenticationException;

public final class EnvironmentCredentialsProvider implements AtiCredentialsProvider {

    public static final String ENV_ACCESS_TOKEN = "ATI_ACCESS_TOKEN";
    public static final String ENV_ACCESS_KEY_ID = "ATI_ACCESS_KEY_ID";
    public static final String ENV_ACCESS_KEY_SECRET = "ATI_ACCESS_KEY_SECRET";

    @Override
    public AtiCredentials resolveCredentials() {
        String accessToken = System.getenv(ENV_ACCESS_TOKEN);
        if (accessToken != null && !accessToken.isBlank()) {
            return AtiCredentials.ofAccessToken(accessToken);
        }

        String accessKeyId = System.getenv(ENV_ACCESS_KEY_ID);
        String accessKeySecret = System.getenv(ENV_ACCESS_KEY_SECRET);

        if (accessKeyId != null && !accessKeyId.isBlank()
                && accessKeySecret != null && !accessKeySecret.isBlank()) {
            return AtiCredentials.ofAccessKey(accessKeyId, accessKeySecret);
        }

        throw new AtiAuthenticationException(
            "No credentials found. Set either " + ENV_ACCESS_TOKEN
            + " or both " + ENV_ACCESS_KEY_ID + " and " + ENV_ACCESS_KEY_SECRET
            + " environment variables.");
    }
}
