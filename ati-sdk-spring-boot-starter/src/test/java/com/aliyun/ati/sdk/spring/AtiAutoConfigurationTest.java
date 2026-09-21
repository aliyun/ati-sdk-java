package com.aliyun.ati.sdk.spring;

import com.aliyun.ati.sdk.agent.AtiClient;
import com.aliyun.ati.sdk.agent.AtiVerifiedClient;
import com.aliyun.ati.sdk.transparency.TransparencyClient;
import com.aliyun.ati.sdk.transparency.verification.BadgeVerificationService;
import com.aliyun.ati.sdk.transparency.verification.SealTrustChain;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for ATI Spring Boot auto-configuration.
 */
class AtiAutoConfigurationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(AtiClientAutoConfiguration.class));

    // ==================== Default Configuration Tests ====================

    @Nested
    @DisplayName("Default configuration")
    class DefaultConfigurationTests {

        @Test
        @DisplayName("Should create TransparencyClient and AtiClient beans with defaults")
        void shouldCreateBeansWithDefaults() {
            contextRunner
                .run(context -> {
                    assertThat(context).hasSingleBean(TransparencyClient.class);
                    assertThat(context).hasSingleBean(AtiClient.class);
                });
        }

        @Test
        @DisplayName("Should create AtiSdkProperties bean")
        void shouldCreatePropertiesBean() {
            contextRunner
                .run(context -> {
                    assertThat(context).hasSingleBean(AtiSdkProperties.class);
                });
        }
    }

    // ==================== Custom Properties Tests ====================

    @Nested
    @DisplayName("Custom properties")
    class CustomPropertiesTests {

        @Test
        @DisplayName("Should apply custom transparency base URL")
        void shouldApplyCustomTransparencyBaseUrl() {
            contextRunner
                .withPropertyValues(
                    "ati.sdk.transparency.base-url=https://ati-tl.cnnic.cn:8180"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(TransparencyClient.class);
                    assertThat(context).hasSingleBean(AtiSdkProperties.class);

                    AtiSdkProperties props = context.getBean(AtiSdkProperties.class);
                    assertThat(props.getTransparency().getBaseUrl())
                        .isEqualTo("https://ati-tl.cnnic.cn:8180");
                });
        }

        @Test
        @DisplayName("Should apply custom client timeout")
        void shouldApplyCustomClientTimeout() {
            contextRunner
                .withPropertyValues(
                    "ati.sdk.client.connect-timeout=15s"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(AtiSdkProperties.class);

                    AtiSdkProperties props = context.getBean(AtiSdkProperties.class);
                    assertThat(props.getClient().getConnectTimeout()).isEqualTo("15s");
                });
        }

        @Test
        @DisplayName("Should reject NONE client verification policy")
        void shouldRejectNoneClientPolicy() {
            contextRunner
                .withPropertyValues("ati.sdk.verification.policy=NONE")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure().getCause())
                        .hasMessageContaining("server-only");
                });
        }

        @Test
        @DisplayName("Should apply verification policy property")
        void shouldApplyVerificationPolicy() {
            contextRunner
                .withPropertyValues(
                    "ati.sdk.verification.policy=ADVANCED"
                )
                .run(context -> {
                    AtiSdkProperties props = context.getBean(AtiSdkProperties.class);
                    assertThat(props.getVerification().getPolicy())
                        .isEqualTo("ADVANCED");
                });
        }
    }

    // ==================== Conditional Tests ====================

    @Nested
    @DisplayName("Conditional behavior")
    class ConditionalTests {

        @Test
        @DisplayName("Should not create beans when disabled")
        void shouldNotCreateBeansWhenDisabled() {
            contextRunner
                .withPropertyValues("ati.sdk.enabled=false")
                .run(context -> {
                    assertThat(context).doesNotHaveBean(TransparencyClient.class);
                    assertThat(context).doesNotHaveBean(AtiClient.class);
                });
        }

        @Test
        @DisplayName("Should back off when user provides custom TransparencyClient bean")
        void shouldBackOffWhenUserProvidesCustomTransparencyClient() {
            contextRunner
                .withUserConfiguration(CustomTransparencyClientConfig.class)
                .run(context -> {
                    assertThat(context).hasSingleBean(TransparencyClient.class);
                    TransparencyClient client = context.getBean(TransparencyClient.class);
                    assertThat(client.getBaseUrl())
                        .isEqualTo("https://ati-tl.cnnic.cn:9090");
                });
        }
    }

    // ==================== Mode Tests ====================

    @Nested
    @DisplayName("Mode configuration")
    class ModeTests {

        @Test
        @DisplayName("Should be client mode by default")
        void shouldBeClientModeByDefault() {
            contextRunner
                .run(context -> {
                    AtiSdkProperties props = context.getBean(AtiSdkProperties.class);
                    assertThat(props.isClientMode()).isTrue();
                    assertThat(props.isServerMode()).isFalse();
                });
        }

        @Test
        @DisplayName("Should support 'both' mode")
        void shouldSupportBothMode() {
            contextRunner
                .withPropertyValues("ati.sdk.mode=both")
                .run(context -> {
                    AtiSdkProperties props = context.getBean(AtiSdkProperties.class);
                    assertThat(props.isClientMode()).isTrue();
                    assertThat(props.isServerMode()).isTrue();
                });
        }

        @Test
        @DisplayName("Should support 'server' mode")
        void shouldSupportServerMode() {
            contextRunner
                .withPropertyValues("ati.sdk.mode=server")
                .run(context -> {
                    AtiSdkProperties props = context.getBean(AtiSdkProperties.class);
                    assertThat(props.isClientMode()).isFalse();
                    assertThat(props.isServerMode()).isTrue();
                });
        }
    }

    // ==================== Seal CA Chain Wiring Tests ====================

    @Nested
    @DisplayName("Seal CA Chain wiring (outbound Connection)")
    class SealTrustChainWiringTests {

        private static final String SHIPPED_SEAL_CHAIN_RESOURCE =
            "/com/aliyun/ati/sdk/transparency/seal/seal-ca-chain.crt";

        @Test
        @DisplayName("Default (no property) injects the shipped Seal CA Chain into AtiVerifiedClient")
        void shouldInjectShippedChainByDefault() {
            contextRunner
                .run(context -> {
                    assertThat(context.getStartupFailure()).isNull();
                    assertThat(context).hasSingleBean(SealTrustChain.class);
                    AtiVerifiedClient client = context.getBean(AtiVerifiedClient.class);
                    assertThat(client.sealTrustChain())
                        .isSameAs(context.getBean(SealTrustChain.class));
                    assertThat(client.sealTrustChain().root().getSubjectX500Principal().getName())
                        .contains("UCA RSA Non-Public Root CA - G1");
                });
        }

        @Test
        @DisplayName("ati.sdk.transparency.seal.trust-certificate injects an override into AtiVerifiedClient")
        void shouldInjectOverrideChainFromProperty(@TempDir Path tempDir) throws Exception {
            Path override = tempDir.resolve("seal-ca-chain.pem");
            try (InputStream in = getClass().getResourceAsStream(SHIPPED_SEAL_CHAIN_RESOURCE)) {
                assertThat(in)
                    .as("shipped Seal CA Chain resource must be on the test classpath")
                    .isNotNull();
                Files.copy(in, override, StandardCopyOption.REPLACE_EXISTING);
            }

            contextRunner
                .withPropertyValues("ati.sdk.transparency.seal.trust-certificate=" + override)
                .run(context -> {
                    assertThat(context.getStartupFailure()).isNull();
                    assertThat(context).hasSingleBean(SealTrustChain.class);
                    AtiVerifiedClient client = context.getBean(AtiVerifiedClient.class);
                    assertThat(client.sealTrustChain())
                        .isSameAs(context.getBean(SealTrustChain.class));
                });
        }

        @Test
        @DisplayName("A malformed (nonexistent) override path fails closed at startup")
        void shouldFailClosedOnMalformedOverride() {
            contextRunner
                .withPropertyValues(
                    "ati.sdk.transparency.seal.trust-certificate=/nonexistent/seal-ca-chain.pem")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                        .hasStackTraceContaining("Seal CA Chain");
                });
        }

        @Test
        @DisplayName("mode=both shares one SealTrustChain between AtiVerifiedClient and BadgeVerificationService")
        void bothModeSharesOneSealTrustChain() {
            new ApplicationContextRunner()
                .withConfiguration(AutoConfigurations.of(
                    AtiClientAutoConfiguration.class, AtiServerAutoConfiguration.class))
                .withPropertyValues("ati.sdk.mode=both")
                .run(context -> {
                    assertThat(context.getStartupFailure()).isNull();
                    assertThat(context).hasSingleBean(SealTrustChain.class);
                    assertThat(context).hasSingleBean(AtiVerifiedClient.class);
                    assertThat(context).hasSingleBean(BadgeVerificationService.class);
                    assertThat(context.getBean(AtiVerifiedClient.class).sealTrustChain())
                        .isSameAs(context.getBean(SealTrustChain.class));
                });
        }
    }

    // ==================== User Override Configurations ====================

    @Configuration(proxyBeanMethods = false)
    static class CustomTransparencyClientConfig {

        @Bean
        TransparencyClient transparencyClient() {
            return TransparencyClient.builder()
                .baseUrl("https://ati-tl.cnnic.cn:9090")
                .build();
        }
    }
}
