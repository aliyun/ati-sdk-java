package com.aliyun.ati.sdk.spring;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;

import com.aliyun.ati.sdk.agent.AtiVerifiedClient;
import com.aliyun.ati.sdk.agent.verification.BadgeVerifier;
import com.aliyun.ati.sdk.agent.verification.DaneTlsaVerifier;
import com.aliyun.ati.sdk.agent.verification.DefaultConnectionVerifier;
import com.aliyun.ati.sdk.discovery.AtiDiscoveryClient;
import com.aliyun.ati.sdk.transparency.AtiTransparencyClient;
import com.aliyun.ati.sdk.transparency.RootKeyManager;
import com.aliyun.ati.sdk.transparency.verification.BadgeVerificationService;
import com.aliyun.ati.sdk.transparency.verification.CachingBadgeVerificationService;
import com.aliyun.ati.sdk.transparency.verification.MerkleProofVerifier;
import com.aliyun.ati.sdk.transparency.verification.TlSealVerifier;

class AtiClientAutoConfigurationTest {

    private final ApplicationContextRunner contextRunner =
        new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(
                AtiClientAutoConfiguration.class));

    @Test
    void shouldRegisterClientBeansWithDefaultMode() {
        contextRunner.run(context -> {
            assertThat(context).hasSingleBean(
                AtiVerifiedClient.class);
            assertThat(context).hasSingleBean(
                AtiTransparencyClient.class);
            assertThat(context).hasSingleBean(RootKeyManager.class);
            assertThat(context).hasSingleBean(TlSealVerifier.class);
            assertThat(context).hasSingleBean(
                MerkleProofVerifier.class);
            assertThat(context).hasSingleBean(
                BadgeVerificationService.class);
            assertThat(context).hasSingleBean(
                CachingBadgeVerificationService.class);
            assertThat(context).hasSingleBean(
                AtiDiscoveryClient.class);
            assertThat(context).hasSingleBean(
                DaneTlsaVerifier.class);
            assertThat(context).hasSingleBean(BadgeVerifier.class);
            assertThat(context).hasSingleBean(
                DefaultConnectionVerifier.class);
        });
    }

    @Test
    void shouldRegisterClientBeansWithExplicitClientMode() {
        contextRunner
            .withPropertyValues("ati.sdk.mode=client")
            .run(context -> {
                assertThat(context).hasSingleBean(
                    AtiVerifiedClient.class);
                assertThat(context).hasSingleBean(
                    AtiTransparencyClient.class);
            });
    }

    @Test
    void shouldNotRegisterClientBeansWithServerMode() {
        contextRunner
            .withPropertyValues("ati.sdk.mode=server")
            .run(context -> {
                assertThat(context).doesNotHaveBean(
                    AtiVerifiedClient.class);
                assertThat(context).doesNotHaveBean(
                    AtiDiscoveryClient.class);
                assertThat(context).doesNotHaveBean(
                    DaneTlsaVerifier.class);
            });
    }
}
