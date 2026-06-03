package com.aliyun.ati.sdk.spring;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import com.aliyun.ati.sdk.agent.AtiVerifiedClient;
import com.aliyun.ati.sdk.agent.server.ClientRequestVerifier;
import com.aliyun.ati.sdk.transparency.AtiTransparencyClient;
import com.aliyun.ati.sdk.transparency.RootKeyManager;
import com.aliyun.ati.sdk.transparency.verification.BadgeVerificationService;
import com.aliyun.ati.sdk.transparency.verification.CachingBadgeVerificationService;
import com.aliyun.ati.sdk.transparency.verification.MerkleProofVerifier;
import com.aliyun.ati.sdk.transparency.verification.TlSealVerifier;

class AtiServerAutoConfigurationTest {

    private final ApplicationContextRunner contextRunner =
        new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(
                AtiServerAutoConfiguration.class));

    @Test
    void shouldRegisterServerBeansWithServerMode() {
        contextRunner
            .withPropertyValues("ati.sdk.mode=server")
            .run(context -> {
                assertThat(context).hasSingleBean(
                    ClientRequestVerifier.class);
                assertThat(context).hasSingleBean(
                    AtiTransparencyClient.class);
                assertThat(context).hasSingleBean(
                    RootKeyManager.class);
                assertThat(context).hasSingleBean(
                    TlSealVerifier.class);
                assertThat(context).hasSingleBean(
                    MerkleProofVerifier.class);
                assertThat(context).hasSingleBean(
                    BadgeVerificationService.class);
                assertThat(context).hasSingleBean(
                    CachingBadgeVerificationService.class);
            });
    }

    @Test
    void shouldNotRegisterServerBeansWithClientMode() {
        contextRunner
            .withPropertyValues("ati.sdk.mode=client")
            .run(context -> {
                assertThat(context).doesNotHaveBean(
                    ClientRequestVerifier.class);
                assertThat(context).doesNotHaveBean(
                    AtiTransparencyClient.class);
                assertThat(context).doesNotHaveBean(
                    AtiVerifiedClient.class);
            });
    }
}
