package com.aliyun.ati.sdk.auth;

import com.aliyun.ati.sdk.exception.AtiAuthenticationException;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class EnvironmentCredentialsProviderTest {

    @Test
    void shouldHaveCorrectEnvVarNames() {
        assertThat(EnvironmentCredentialsProvider.ENV_ACCESS_TOKEN)
            .isEqualTo("ATI_ACCESS_TOKEN");
        assertThat(EnvironmentCredentialsProvider.ENV_ACCESS_KEY_ID)
            .isEqualTo("ATI_ACCESS_KEY_ID");
        assertThat(EnvironmentCredentialsProvider.ENV_ACCESS_KEY_SECRET)
            .isEqualTo("ATI_ACCESS_KEY_SECRET");
    }

    @Test
    void shouldThrowWhenNoEnvVarsSet() {
        EnvironmentCredentialsProvider provider = new EnvironmentCredentialsProvider();

        assertThatThrownBy(provider::resolveCredentials)
            .isInstanceOf(AtiAuthenticationException.class)
            .hasMessageContaining("No credentials found");
    }
}
