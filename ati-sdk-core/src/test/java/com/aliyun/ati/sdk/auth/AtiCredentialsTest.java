package com.aliyun.ati.sdk.auth;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AtiCredentialsTest {

    @Test
    void shouldCreateAccessTokenCredentials() {
        AtiCredentials creds = AtiCredentials.ofAccessToken("my-token");

        assertThat(creds.getType())
            .isEqualTo(AtiCredentials.CredentialType.ACCESS_TOKEN);
        assertThat(creds.getAccessToken()).isEqualTo("my-token");
        assertThat(creds.getAccessKeyId()).isNull();
        assertThat(creds.getAccessKeySecret()).isNull();
    }

    @Test
    void shouldCreateAccessKeyCredentials() {
        AtiCredentials creds = AtiCredentials.ofAccessKey("key-id", "key-secret");

        assertThat(creds.getType())
            .isEqualTo(AtiCredentials.CredentialType.ACCESS_KEY);
        assertThat(creds.getAccessKeyId()).isEqualTo("key-id");
        assertThat(creds.getAccessKeySecret()).isEqualTo("key-secret");
        assertThat(creds.getAccessToken()).isNull();
    }

    @Test
    void shouldGenerateBearerAuthHeader() {
        AtiCredentials creds = AtiCredentials.ofAccessToken("my-token");
        assertThat(creds.toAuthorizationHeader()).isEqualTo("Bearer my-token");
    }

    @Test
    void shouldGenerateAccessKeyAuthHeader() {
        AtiCredentials creds = AtiCredentials.ofAccessKey("key-id", "key-secret");
        assertThat(creds.toAuthorizationHeader())
            .isEqualTo("AccessKey key-id:key-secret");
    }

    @Test
    void shouldRejectNullToken() {
        assertThatThrownBy(() -> AtiCredentials.ofAccessToken(null))
            .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void shouldRejectBlankToken() {
        assertThatThrownBy(() -> AtiCredentials.ofAccessToken("  "))
            .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void shouldRejectNullAccessKeyId() {
        assertThatThrownBy(() -> AtiCredentials.ofAccessKey(null, "secret"))
            .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void shouldRejectNullAccessKeySecret() {
        assertThatThrownBy(() -> AtiCredentials.ofAccessKey("key", null))
            .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void shouldRejectBlankAccessKeyId() {
        assertThatThrownBy(() -> AtiCredentials.ofAccessKey("", "secret"))
            .isInstanceOf(IllegalArgumentException.class);
    }
}
