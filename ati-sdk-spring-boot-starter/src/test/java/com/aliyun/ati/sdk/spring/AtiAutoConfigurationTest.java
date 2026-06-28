package com.aliyun.ati.sdk.spring;

import com.aliyun.ati.sdk.agent.AtiClient;
import com.aliyun.ati.sdk.transparency.TransparencyClient;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

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
                    "ati.sdk.transparency.base-url=https://tl.atiagent.cn:8180"
                )
                .run(context -> {
                    assertThat(context).hasSingleBean(TransparencyClient.class);
                    assertThat(context).hasSingleBean(AtiSdkProperties.class);

                    AtiSdkProperties props = context.getBean(AtiSdkProperties.class);
                    assertThat(props.getTransparency().getBaseUrl())
                        .isEqualTo("https://tl.atiagent.cn:8180");
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
        @DisplayName("Should apply verification policy property")
        void shouldApplyVerificationPolicy() {
            contextRunner
                .withPropertyValues(
                    "ati.sdk.verification.policy=DANE_AND_BADGE"
                )
                .run(context -> {
                    AtiSdkProperties props = context.getBean(AtiSdkProperties.class);
                    assertThat(props.getVerification().getPolicy())
                        .isEqualTo("DANE_AND_BADGE");
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
                        .isEqualTo("https://tl.atiagent.cn:9090");
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

    // ==================== User Override Configurations ====================

    @Configuration(proxyBeanMethods = false)
    static class CustomTransparencyClientConfig {

        @Bean
        TransparencyClient transparencyClient() {
            return TransparencyClient.builder()
                .baseUrl("https://tl.atiagent.cn:9090")
                .build();
        }
    }
}
