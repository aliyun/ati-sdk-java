package com.aliyun.ati.sdk.auth;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AccessKeyCredentialsProviderTest {

    @Test
    void shouldResolveStaticAccessKey() {
        AccessKeyCredentialsProvider provider =
            new AccessKeyCredentialsProvider("my-key", "my-secret");

        AtiCredentials creds = provider.resolveCredentials();

        assertThat(creds.getType())
            .isEqualTo(AtiCredentials.CredentialType.ACCESS_KEY);
        assertThat(creds.getAccessKeyId()).isEqualTo("my-key");
        assertThat(creds.getAccessKeySecret()).isEqualTo("my-secret");
    }

    @Test
    void shouldReturnSameInstanceOnMultipleCalls() {
        AccessKeyCredentialsProvider provider =
            new AccessKeyCredentialsProvider("my-key", "my-secret");

        AtiCredentials first = provider.resolveCredentials();
        AtiCredentials second = provider.resolveCredentials();

        assertThat(first).isSameAs(second);
    }
}
