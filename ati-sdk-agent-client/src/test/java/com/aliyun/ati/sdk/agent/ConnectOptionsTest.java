package com.aliyun.ati.sdk.agent;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ConnectOptionsTest {

    @Test
    void shouldHaveDefaultValues() {
        ConnectOptions options = ConnectOptions.builder().build();

        assertThat(options.getPolicy())
            .isEqualTo(VerificationPolicy.DANE_AND_BADGE);
        assertThat(options.getPort()).isEqualTo(443);
        assertThat(options.getKeystorePath()).isNull();
        assertThat(options.getKeystorePassword()).isNull();
    }

    @Test
    void shouldOverrideValues() {
        ConnectOptions options = ConnectOptions.builder()
            .policy(VerificationPolicy.PKI_ONLY)
            .port(8443)
            .keystorePath("/tmp/keystore.p12")
            .keystorePassword("secret")
            .build();

        assertThat(options.getPolicy())
            .isEqualTo(VerificationPolicy.PKI_ONLY);
        assertThat(options.getPort()).isEqualTo(8443);
        assertThat(options.getKeystorePath())
            .isEqualTo("/tmp/keystore.p12");
        assertThat(options.getKeystorePassword())
            .isEqualTo("secret");
    }

    @Test
    void shouldUseBuilderPattern() {
        ConnectOptions.Builder builder = ConnectOptions.builder();

        ConnectOptions.Builder returned = builder
            .policy(VerificationPolicy.BADGE_REQUIRED);
        assertThat(returned).isSameAs(builder);

        returned = builder.port(9443);
        assertThat(returned).isSameAs(builder);

        returned = builder.keystorePath("/tmp/ks.p12");
        assertThat(returned).isSameAs(builder);

        returned = builder.keystorePassword("pw");
        assertThat(returned).isSameAs(builder);
    }
}
