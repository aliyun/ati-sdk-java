package com.aliyun.ati.sdk.spring;

import com.aliyun.ati.sdk.transparency.TransparencyClient;
import com.aliyun.ati.sdk.transparency.verification.BadgeVerificationService;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;

import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/**
 * Tests for {@link AtiServerAutoConfiguration}.
 */
class AtiServerAutoConfigurationTest {

    private final ApplicationContextRunner contextRunner = new ApplicationContextRunner()
        .withConfiguration(AutoConfigurations.of(AtiServerAutoConfiguration.class));

    // ==================== Bean Creation Tests ====================

    @Nested
    @DisplayName("Bean creation")
    class BeanCreationTests {

        @Test
        @DisplayName("Should create atiServerCustomizer bean by default")
        void shouldCreateAtiServerCustomizerByDefault() {
            contextRunner
                .run(context -> {
                    assertThat(context).hasSingleBean(WebServerFactoryCustomizer.class);
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

        @Test
        @DisplayName("Should not create beans when disabled")
        void shouldNotCreateBeansWhenDisabled() {
            contextRunner
                .withPropertyValues("ati.sdk.enabled=false")
                .run(context -> {
                    assertThat(context)
                        .doesNotHaveBean(WebServerFactoryCustomizer.class);
                });
        }
    }

    // ==================== Mode Tests ====================

    @Nested
    @DisplayName("Mode configuration")
    class ModeTests {

        @Test
        @DisplayName("Should have customizer bean when mode=server")
        void shouldHaveCustomizerWhenModeIsServer() {
            contextRunner
                .withPropertyValues("ati.sdk.mode=server")
                .run(context -> {
                    assertThat(context)
                        .hasSingleBean(WebServerFactoryCustomizer.class);

                    AtiSdkProperties props =
                        context.getBean(AtiSdkProperties.class);
                    assertThat(props.isServerMode()).isTrue();
                });
        }

        @Test
        @DisplayName("Should have customizer bean when mode=both")
        void shouldHaveCustomizerWhenModeIsBoth() {
            contextRunner
                .withPropertyValues("ati.sdk.mode=both")
                .run(context -> {
                    assertThat(context)
                        .hasSingleBean(WebServerFactoryCustomizer.class);

                    AtiSdkProperties props =
                        context.getBean(AtiSdkProperties.class);
                    assertThat(props.isServerMode()).isTrue();
                    assertThat(props.isClientMode()).isTrue();
                });
        }

        @Test
        @DisplayName("Should still create customizer bean in client mode")
        void shouldCreateCustomizerInClientMode() {
            // The customizer bean is always created; it checks mode internally
            contextRunner
                .withPropertyValues("ati.sdk.mode=client")
                .run(context -> {
                    assertThat(context)
                        .hasSingleBean(WebServerFactoryCustomizer.class);

                    AtiSdkProperties props =
                        context.getBean(AtiSdkProperties.class);
                    assertThat(props.isServerMode()).isFalse();
                });
        }
    }

    // ==================== IDCA Trust Certificate Tests ====================

    @Nested
    @DisplayName("IDCA trust certificate configuration")
    class IdcaTrustCertificateTests {

        @Test
        @DisplayName("Should configure IDCA trust-certificate from properties")
        void shouldConfigureIdcaTrustCertificate() {
            contextRunner
                .withPropertyValues(
                    "ati.sdk.mode=server",
                    "ati.sdk.server.idca.trust-certificate=/path/to/idca.pem"
                )
                .run(context -> {
                    AtiSdkProperties props =
                        context.getBean(AtiSdkProperties.class);

                    assertThat(props.getServer().getIdca()
                        .getTrustCertificate())
                        .isEqualTo("/path/to/idca.pem");
                });
        }

        @Test
        @DisplayName("IDCA trust-certificate should be null by default")
        void idcaTrustCertificateShouldBeNullByDefault() {
            contextRunner
                .withPropertyValues("ati.sdk.mode=server")
                .run(context -> {
                    AtiSdkProperties props =
                        context.getBean(AtiSdkProperties.class);

                    assertThat(props.getServer().getIdca()
                        .getTrustCertificate())
                        .isNull();
                });
        }
    }

    // ==================== Server Properties via Spring ====================

    @Nested
    @DisplayName("Server property binding")
    class ServerPropertyBindingTests {

        @Test
        @DisplayName("Should bind server port from properties")
        void shouldBindServerPort() {
            contextRunner
                .withPropertyValues(
                    "ati.sdk.mode=server",
                    "ati.sdk.server.port=8443"
                )
                .run(context -> {
                    AtiSdkProperties props =
                        context.getBean(AtiSdkProperties.class);

                    assertThat(props.getServer().getPort()).isEqualTo(8443);
                });
        }

        @Test
        @DisplayName("Should bind server certificate from properties")
        void shouldBindServerCertificate() {
            contextRunner
                .withPropertyValues(
                    "ati.sdk.mode=server",
                    "ati.sdk.server.certificate=/path/to/server.crt",
                    "ati.sdk.server.private-key=/path/to/server.key"
                )
                .run(context -> {
                    AtiSdkProperties props =
                        context.getBean(AtiSdkProperties.class);

                    assertThat(props.getServer().getCertificate())
                        .isEqualTo("/path/to/server.crt");
                    assertThat(props.getServer().getPrivateKey())
                        .isEqualTo("/path/to/server.key");
                });
        }

        @Test
        @DisplayName("Should bind server verification policy")
        void shouldBindServerVerificationPolicy() {
            contextRunner
                .withPropertyValues(
                    "ati.sdk.mode=server",
                    "ati.sdk.server.verification.policy=ADVANCED"
                )
                .run(context -> {
                    AtiSdkProperties props =
                        context.getBean(AtiSdkProperties.class);

                    assertThat(props.getServer().getVerification().getPolicy())
                        .isEqualTo("ADVANCED");
                });
        }

        @Test
        @DisplayName("Server port should default to 443")
        void serverPortShouldDefaultTo443() {
            contextRunner
                .withPropertyValues("ati.sdk.mode=server")
                .run(context -> {
                    AtiSdkProperties props =
                        context.getBean(AtiSdkProperties.class);

                    assertThat(props.getServer().getPort()).isEqualTo(443);
                });
        }
    }

    // ==================== Seal CA Chain Wiring Tests ====================

    @Nested
    @DisplayName("Seal CA Chain wiring (BadgeVerificationService)")
    class SealTrustChainWiringTests {

        /** Classpath location of the SDK-shipped production Seal CA Chain (Root + Intermediate). */
        private static final String SHIPPED_SEAL_CHAIN_RESOURCE =
            "/com/aliyun/ati/sdk/transparency/seal/seal-ca-chain.crt";

        @Test
        @DisplayName("Default (no property) builds the badge service on the shipped Seal CA Chain")
        void shouldCreateBadgeServiceWithShippedChainByDefault() {
            contextRunner
                .withBean(TransparencyClient.class, () -> mock(TransparencyClient.class))
                .withPropertyValues("ati.sdk.mode=server")
                .run(context -> {
                    assertThat(context.getStartupFailure()).isNull();
                    assertThat(context).hasSingleBean(BadgeVerificationService.class);
                });
        }

        @Test
        @DisplayName("ati.sdk.transparency.seal.trust-certificate injects an override chain end-to-end")
        void shouldInjectOverrideChainFromProperty(@TempDir Path tempDir) throws Exception {
            Path override = tempDir.resolve("seal-ca-chain.pem");
            try (InputStream in = getClass().getResourceAsStream(SHIPPED_SEAL_CHAIN_RESOURCE)) {
                assertThat(in)
                    .as("shipped Seal CA Chain resource must be on the test classpath")
                    .isNotNull();
                Files.copy(in, override, StandardCopyOption.REPLACE_EXISTING);
            }

            contextRunner
                .withBean(TransparencyClient.class, () -> mock(TransparencyClient.class))
                .withPropertyValues(
                    "ati.sdk.mode=server",
                    "ati.sdk.transparency.seal.trust-certificate=" + override)
                .run(context -> {
                    assertThat(context.getStartupFailure()).isNull();
                    assertThat(context).hasSingleBean(BadgeVerificationService.class);
                });
        }

        @Test
        @DisplayName("A malformed (nonexistent) override path fails closed at startup")
        void shouldFailClosedOnMalformedOverride() {
            contextRunner
                .withBean(TransparencyClient.class, () -> mock(TransparencyClient.class))
                .withPropertyValues(
                    "ati.sdk.mode=server",
                    "ati.sdk.transparency.seal.trust-certificate=/nonexistent/seal-ca-chain.pem")
                .run(context -> {
                    assertThat(context).hasFailed();
                    assertThat(context.getStartupFailure())
                        .hasStackTraceContaining("Seal CA Chain");
                });
        }
    }
}
