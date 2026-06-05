package com.aliyun.ati.sdk.agent;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ConnectOptionsTest {

    @Test
    void shouldHaveDefaultValues() {
        ConnectOptions options = ConnectOptions.builder().build();

        assertThat(options.getPolicy())
            .isEqualTo(VerificationPolicy.GOLD);
        assertThat(options.getPort()).isEqualTo(443);
    }

    @Test
    void shouldOverrideValues() {
        ConnectOptions options = ConnectOptions.builder()
            .policy(VerificationPolicy.BRONZE)
            .port(8443)
            .build();

        assertThat(options.getPolicy())
            .isEqualTo(VerificationPolicy.BRONZE);
        assertThat(options.getPort()).isEqualTo(8443);
    }

    @Test
    void shouldUseBuilderPattern() {
        ConnectOptions.Builder builder = ConnectOptions.builder();

        ConnectOptions.Builder returned = builder
            .policy(VerificationPolicy.SILVER);
        assertThat(returned).isSameAs(builder);

        returned = builder.port(9443);
        assertThat(returned).isSameAs(builder);
    }
}
