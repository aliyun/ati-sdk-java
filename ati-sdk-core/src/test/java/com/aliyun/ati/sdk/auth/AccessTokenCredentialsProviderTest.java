package com.aliyun.ati.sdk.auth;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AccessTokenCredentialsProviderTest {

    @Test
    void shouldResolveStaticToken() {
        AccessTokenCredentialsProvider provider =
            new AccessTokenCredentialsProvider("test-token");

        AtiCredentials creds = provider.resolveCredentials();

        assertThat(creds.getType())
            .isEqualTo(AtiCredentials.CredentialType.ACCESS_TOKEN);
        assertThat(creds.getAccessToken()).isEqualTo("test-token");
    }

    @Test
    void shouldReturnSameInstanceOnMultipleCalls() {
        AccessTokenCredentialsProvider provider =
            new AccessTokenCredentialsProvider("test-token");

        AtiCredentials first = provider.resolveCredentials();
        AtiCredentials second = provider.resolveCredentials();

        assertThat(first).isSameAs(second);
    }
}
