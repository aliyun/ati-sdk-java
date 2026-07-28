package com.aliyun.ati.sdk.spring;

import com.aliyun.ati.sdk.agent.VerificationPolicy;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;

import static org.assertj.core.api.Assertions.assertThat;

class AtiServerSslCustomizerTest {

    @Test
    @DisplayName("Should enable CRL checking when IDCA trust is configured and policy is not NONE")
    void shouldEnableCrlCheckingWhenIdcaConfigured() {
        assertThat(AtiServerAutoConfiguration.shouldInstallCrlChecking(true, VerificationPolicy.BASIC))
            .isTrue();
        assertThat(AtiServerAutoConfiguration.shouldInstallCrlChecking(true, VerificationPolicy.ENHANCED))
            .isTrue();
    }

    @Test
    @DisplayName("Should skip CRL checking when policy is NONE or IDCA trust is absent")
    void shouldSkipCrlCheckingForNoneOrMissingIdca() {
        assertThat(AtiServerAutoConfiguration.shouldInstallCrlChecking(true, VerificationPolicy.NONE))
            .isFalse();
        assertThat(AtiServerAutoConfiguration.shouldInstallCrlChecking(false, VerificationPolicy.BASIC))
            .isFalse();
    }

    @Test
    @DisplayName("Should enable SSL when server mode and certificate paths are configured")
    void shouldEnableSslInServerMode() {
        new WebApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(AtiServerAutoConfiguration.class))
            .withPropertyValues(
                "ati.sdk.mode=server",
                "ati.sdk.server.port=0",
                "ati.sdk.server.verification.policy=BASIC",
                "ati.sdk.server.certificate=/tmp/server.pem",
                "ati.sdk.server.private-key=/tmp/server.key",
                "ati.sdk.server.idca.trust-certificate=/tmp/idca.pem"
            )
            .run(context -> {
                AtiSdkProperties properties = context.getBean(AtiSdkProperties.class);
                assertThat(properties.isServerMode()).isTrue();
                assertThat(properties.getServer().getCertificate()).isEqualTo("/tmp/server.pem");
            });
    }

    @Test
    @DisplayName("Should skip server customization in client mode")
    void shouldSkipCustomizationInClientMode() {
        new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(AtiServerAutoConfiguration.class))
            .withPropertyValues("ati.sdk.mode=client")
            .run(context -> {
                AtiSdkProperties properties = context.getBean(AtiSdkProperties.class);
                assertThat(properties.isServerMode()).isFalse();
            });
    }
}
