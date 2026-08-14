package com.aliyun.ati.sdk.spring;

import com.aliyun.ati.sdk.agent.VerificationPolicy;
import com.aliyun.ati.sdk.agent.verification.IdcaChain;
import com.aliyun.ati.sdk.crypto.CertificateUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.autoconfigure.AutoConfigurations;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.boot.test.context.runner.WebApplicationContextRunner;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.Ssl;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.boot.web.servlet.server.ConfigurableServletWebServerFactory;

import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

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
    @DisplayName("Should skip CRL checking when policy is NONE")
    void shouldSkipCrlCheckingForNone() {
        assertThat(AtiServerAutoConfiguration.shouldInstallCrlChecking(true, VerificationPolicy.NONE))
            .isFalse();
        assertThat(AtiServerAutoConfiguration.shouldInstallCrlChecking(false, VerificationPolicy.BASIC))
            .isFalse();
    }

    @Test
    @DisplayName("ENHANCED without trust-certificate uses shipped IDCA Chain")
    void enhancedWithoutPathUsesShippedChain() {
        assertThat(customizeServer("ati.sdk.mode=server", "ati.sdk.server.verification.policy=ENHANCED"))
            .satisfies(ssl -> {
                assertThat(ssl.getClientAuth()).isEqualTo(Ssl.ClientAuth.NEED);
                assertThat(ssl.getTrustCertificate()).isEqualTo(IdcaChain.SHIPPED_CLASSPATH_LOCATION);
            });
    }

    @Test
    @DisplayName("BASIC without trust-certificate uses shipped IDCA Chain")
    void basicWithoutPathUsesShippedChain() {
        assertThat(customizeServer("ati.sdk.mode=server", "ati.sdk.server.verification.policy=BASIC"))
            .satisfies(ssl -> {
                assertThat(ssl.getClientAuth()).isEqualTo(Ssl.ClientAuth.WANT);
                assertThat(ssl.getTrustCertificate()).isEqualTo(IdcaChain.SHIPPED_CLASSPATH_LOCATION);
            });
    }

    @Test
    @DisplayName("NONE does not load IDCA Chain")
    void noneDoesNotLoadIdcaChain() {
        assertThat(customizeServer("ati.sdk.mode=server", "ati.sdk.server.verification.policy=NONE"))
            .satisfies(ssl -> {
                assertThat(ssl.getClientAuth()).isEqualTo(Ssl.ClientAuth.NONE);
                assertThat(ssl.getTrustCertificate()).isNull();
            });
    }

    @Test
    @DisplayName("trust-certificate override replaces shipped IDCA Chain")
    void trustCertificateOverrideReplacesShippedChain(@TempDir Path tempDir) throws Exception {
        IdcaChain shipped = IdcaChain.shipped();
        Path override = tempDir.resolve("override.pem");
        Files.writeString(override,
            CertificateUtils.toPem(shipped.root())
                + CertificateUtils.toPem(shipped.intermediate()),
            StandardCharsets.US_ASCII);

        assertThat(customizeServer(
            "ati.sdk.mode=server",
            "ati.sdk.server.verification.policy=ENHANCED",
            "ati.sdk.server.idca.trust-certificate=" + override
        )).satisfies(ssl -> assertThat(ssl.getTrustCertificate()).isEqualTo(override.toString()));
    }

    @Test
    @DisplayName("Invalid trust-certificate override fails closed")
    void invalidOverrideFailsClosed(@TempDir Path tempDir) throws Exception {
        Path oneCert = tempDir.resolve("one.pem");
        Files.writeString(oneCert,
            CertificateUtils.toPem(IdcaChain.shipped().root()),
            StandardCharsets.US_ASCII);

        new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(AtiServerAutoConfiguration.class))
            .withPropertyValues(
                "ati.sdk.mode=server",
                "ati.sdk.server.verification.policy=ENHANCED",
                "ati.sdk.server.idca.trust-certificate=" + oneCert
            )
            .run(context -> {
                @SuppressWarnings("unchecked")
                WebServerFactoryCustomizer<ConfigurableServletWebServerFactory> customizer =
                    context.getBean("atiServerCustomizer", WebServerFactoryCustomizer.class);
                TomcatServletWebServerFactory factory = new TomcatServletWebServerFactory();
                assertThatThrownBy(() -> customizer.customize(factory))
                    .isInstanceOf(IllegalStateException.class)
                    .hasMessageContaining("exactly 2");
            });
    }

    private Ssl customizeServer(String... properties) {
        var holder = new Ssl[1];
        new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(AtiServerAutoConfiguration.class))
            .withPropertyValues(properties)
            .run(context -> {
                @SuppressWarnings("unchecked")
                WebServerFactoryCustomizer<ConfigurableServletWebServerFactory> customizer =
                    context.getBean("atiServerCustomizer", WebServerFactoryCustomizer.class);
                TomcatServletWebServerFactory factory = new TomcatServletWebServerFactory();
                customizer.customize(factory);
                holder[0] = factory.getSsl();
            });
        return holder[0];
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
    @DisplayName("Should skip CrlRevocationChecker bean in client mode")
    void shouldSkipCrlRevocationCheckerInClientMode() {
        new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(AtiServerAutoConfiguration.class))
            .withPropertyValues("ati.sdk.mode=client")
            .run(context -> assertThat(context.getBeansOfType(
                com.aliyun.ati.sdk.agent.verification.crl.CrlRevocationChecker.class))
                .isEmpty());
    }

    @Test
    @DisplayName("Should create CrlRevocationChecker bean in server mode")
    void shouldCreateCrlRevocationCheckerInServerMode() {
        new ApplicationContextRunner()
            .withConfiguration(AutoConfigurations.of(AtiServerAutoConfiguration.class))
            .withPropertyValues("ati.sdk.mode=server")
            .run(context -> assertThat(context.getBean(
                com.aliyun.ati.sdk.agent.verification.crl.CrlRevocationChecker.class))
                .isNotNull());
    }
}
