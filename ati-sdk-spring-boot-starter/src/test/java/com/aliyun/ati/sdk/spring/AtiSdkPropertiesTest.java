package com.aliyun.ati.sdk.spring;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link AtiSdkProperties}.
 */
class AtiSdkPropertiesTest {

    // ==================== Top-level Properties ====================

    @Nested
    @DisplayName("Top-level properties")
    class TopLevelTests {

        @Test
        @DisplayName("mode should default to 'client'")
        void modeShouldDefaultToClient() {
            AtiSdkProperties props = new AtiSdkProperties();
            assertThat(props.getMode()).isEqualTo("client");
        }

        @Test
        @DisplayName("enabled should default to true")
        void enabledShouldDefaultToTrue() {
            AtiSdkProperties props = new AtiSdkProperties();
            assertThat(props.isEnabled()).isTrue();
        }

        @Test
        @DisplayName("Should set and get mode")
        void shouldSetAndGetMode() {
            AtiSdkProperties props = new AtiSdkProperties();
            props.setMode("server");
            assertThat(props.getMode()).isEqualTo("server");
        }

        @Test
        @DisplayName("Should set and get enabled")
        void shouldSetAndGetEnabled() {
            AtiSdkProperties props = new AtiSdkProperties();
            props.setEnabled(false);
            assertThat(props.isEnabled()).isFalse();
        }
    }

    // ==================== Mode Helper Methods ====================

    @Nested
    @DisplayName("Mode helper methods")
    class ModeHelperTests {

        @Test
        @DisplayName("isClientMode should return true for 'client'")
        void isClientModeShouldReturnTrueForClient() {
            AtiSdkProperties props = new AtiSdkProperties();
            props.setMode("client");

            assertThat(props.isClientMode()).isTrue();
            assertThat(props.isServerMode()).isFalse();
        }

        @Test
        @DisplayName("isServerMode should return true for 'server'")
        void isServerModeShouldReturnTrueForServer() {
            AtiSdkProperties props = new AtiSdkProperties();
            props.setMode("server");

            assertThat(props.isClientMode()).isFalse();
            assertThat(props.isServerMode()).isTrue();
        }

        @Test
        @DisplayName("Both modes should return true for 'both'")
        void bothModesShouldReturnTrueForBoth() {
            AtiSdkProperties props = new AtiSdkProperties();
            props.setMode("both");

            assertThat(props.isClientMode()).isTrue();
            assertThat(props.isServerMode()).isTrue();
        }

        @Test
        @DisplayName("Mode checks should be case-insensitive")
        void modeChecksShouldBeCaseInsensitive() {
            AtiSdkProperties props = new AtiSdkProperties();

            props.setMode("CLIENT");
            assertThat(props.isClientMode()).isTrue();

            props.setMode("Server");
            assertThat(props.isServerMode()).isTrue();

            props.setMode("BOTH");
            assertThat(props.isClientMode()).isTrue();
            assertThat(props.isServerMode()).isTrue();
        }

        @Test
        @DisplayName("Unknown mode should return false for both helpers")
        void unknownModeShouldReturnFalseForBothHelpers() {
            AtiSdkProperties props = new AtiSdkProperties();
            props.setMode("unknown");

            assertThat(props.isClientMode()).isFalse();
            assertThat(props.isServerMode()).isFalse();
        }
    }

    // ==================== Discovery Properties ====================

    @Nested
    @DisplayName("Discovery properties")
    class DiscoveryTests {

        @Test
        @DisplayName("endpoint should default to alidns.aliyuncs.com")
        void endpointShouldHaveDefault() {
            AtiSdkProperties props = new AtiSdkProperties();

            assertThat(props.getDiscovery().getEndpoint())
                .isEqualTo("alidns.aliyuncs.com");
        }

        @Test
        @DisplayName("accessKeyId should default to null")
        void accessKeyIdShouldDefaultToNull() {
            AtiSdkProperties props = new AtiSdkProperties();

            assertThat(props.getDiscovery().getAccessKeyId()).isNull();
        }

        @Test
        @DisplayName("accessKeySecret should default to null")
        void accessKeySecretShouldDefaultToNull() {
            AtiSdkProperties props = new AtiSdkProperties();

            assertThat(props.getDiscovery().getAccessKeySecret()).isNull();
        }

        @Test
        @DisplayName("Should set and get discovery properties")
        void shouldSetAndGetDiscoveryProperties() {
            AtiSdkProperties props = new AtiSdkProperties();
            AtiSdkProperties.Discovery discovery = props.getDiscovery();

            discovery.setEndpoint("custom.endpoint.com");
            discovery.setAccessKeyId("ak-123");
            discovery.setAccessKeySecret("sk-456");

            assertThat(discovery.getEndpoint()).isEqualTo("custom.endpoint.com");
            assertThat(discovery.getAccessKeyId()).isEqualTo("ak-123");
            assertThat(discovery.getAccessKeySecret()).isEqualTo("sk-456");
        }

        @Test
        @DisplayName("Should replace entire discovery object")
        void shouldReplaceEntireDiscoveryObject() {
            AtiSdkProperties props = new AtiSdkProperties();
            AtiSdkProperties.Discovery newDiscovery = new AtiSdkProperties.Discovery();
            newDiscovery.setEndpoint("new.endpoint.com");

            props.setDiscovery(newDiscovery);

            assertThat(props.getDiscovery().getEndpoint())
                .isEqualTo("new.endpoint.com");
        }
    }

    // ==================== Identity Properties ====================

    @Nested
    @DisplayName("Identity properties")
    class IdentityTests {

        @Test
        @DisplayName("Should default to null certificate and private key")
        void shouldDefaultToNullCertificateAndPrivateKey() {
            AtiSdkProperties props = new AtiSdkProperties();

            assertThat(props.getIdentity().getCertificate()).isNull();
            assertThat(props.getIdentity().getPrivateKey()).isNull();
        }

        @Test
        @DisplayName("Should set and get identity properties")
        void shouldSetAndGetIdentityProperties() {
            AtiSdkProperties props = new AtiSdkProperties();
            AtiSdkProperties.Identity identity = props.getIdentity();

            identity.setCertificate("/path/to/cert.pem");
            identity.setPrivateKey("/path/to/key.pem");

            assertThat(identity.getCertificate()).isEqualTo("/path/to/cert.pem");
            assertThat(identity.getPrivateKey()).isEqualTo("/path/to/key.pem");
        }

        @Test
        @DisplayName("Should replace entire identity object")
        void shouldReplaceEntireIdentityObject() {
            AtiSdkProperties props = new AtiSdkProperties();
            AtiSdkProperties.Identity newIdentity = new AtiSdkProperties.Identity();
            newIdentity.setCertificate("/new/cert.pem");

            props.setIdentity(newIdentity);

            assertThat(props.getIdentity().getCertificate())
                .isEqualTo("/new/cert.pem");
        }
    }

    // ==================== Transparency Properties ====================

    @Nested
    @DisplayName("Transparency properties")
    class TransparencyTests {

        @Test
        @DisplayName("baseUrl should default to transparency log URL")
        void baseUrlShouldHaveDefault() {
            AtiSdkProperties props = new AtiSdkProperties();

            assertThat(props.getTransparency().getBaseUrl())
                .isEqualTo("https://tl.atiagent.cn:8180");
        }

        @Test
        @DisplayName("Should set and get baseUrl")
        void shouldSetAndGetBaseUrl() {
            AtiSdkProperties props = new AtiSdkProperties();
            props.getTransparency().setBaseUrl("https://custom-tl.example.com");

            assertThat(props.getTransparency().getBaseUrl())
                .isEqualTo("https://custom-tl.example.com");
        }

        @Test
        @DisplayName("Should replace entire transparency object")
        void shouldReplaceEntireTransparencyObject() {
            AtiSdkProperties props = new AtiSdkProperties();
            AtiSdkProperties.Transparency newTransparency =
                new AtiSdkProperties.Transparency();
            newTransparency.setBaseUrl("https://new-tl.example.com");

            props.setTransparency(newTransparency);

            assertThat(props.getTransparency().getBaseUrl())
                .isEqualTo("https://new-tl.example.com");
        }
    }

    // ==================== Verification Properties ====================

    @Nested
    @DisplayName("Verification properties")
    class VerificationTests {

        @Test
        @DisplayName("policy should default to BADGE_REQUIRED")
        void policyShouldDefaultToBadgeRequired() {
            AtiSdkProperties props = new AtiSdkProperties();

            assertThat(props.getVerification().getPolicy())
                .isEqualTo("BADGE_REQUIRED");
        }

        @Test
        @DisplayName("Should set and get policy")
        void shouldSetAndGetPolicy() {
            AtiSdkProperties props = new AtiSdkProperties();
            props.getVerification().setPolicy("DANE_AND_BADGE");

            assertThat(props.getVerification().getPolicy())
                .isEqualTo("DANE_AND_BADGE");
        }

        @Test
        @DisplayName("Should replace entire verification object")
        void shouldReplaceEntireVerificationObject() {
            AtiSdkProperties props = new AtiSdkProperties();
            AtiSdkProperties.Verification newVerification =
                new AtiSdkProperties.Verification();
            newVerification.setPolicy("PKI_ONLY");

            props.setVerification(newVerification);

            assertThat(props.getVerification().getPolicy())
                .isEqualTo("PKI_ONLY");
        }
    }

    // ==================== Client Properties ====================

    @Nested
    @DisplayName("Client properties")
    class ClientTests {

        @Test
        @DisplayName("dnsTimeout should default to 5s")
        void dnsTimeoutShouldDefaultTo5s() {
            AtiSdkProperties props = new AtiSdkProperties();

            assertThat(props.getClient().getDnsTimeout()).isEqualTo("5s");
        }

        @Test
        @DisplayName("connectTimeout should default to 10s")
        void connectTimeoutShouldDefaultTo10s() {
            AtiSdkProperties props = new AtiSdkProperties();

            assertThat(props.getClient().getConnectTimeout()).isEqualTo("10s");
        }

        @Test
        @DisplayName("Should set and get client timeouts")
        void shouldSetAndGetClientTimeouts() {
            AtiSdkProperties props = new AtiSdkProperties();
            AtiSdkProperties.Client client = props.getClient();

            client.setDnsTimeout("3s");
            client.setConnectTimeout("15s");

            assertThat(client.getDnsTimeout()).isEqualTo("3s");
            assertThat(client.getConnectTimeout()).isEqualTo("15s");
        }

        @Test
        @DisplayName("Should replace entire client object")
        void shouldReplaceEntireClientObject() {
            AtiSdkProperties props = new AtiSdkProperties();
            AtiSdkProperties.Client newClient = new AtiSdkProperties.Client();
            newClient.setConnectTimeout("30s");

            props.setClient(newClient);

            assertThat(props.getClient().getConnectTimeout()).isEqualTo("30s");
        }
    }

    // ==================== Server Properties ====================

    @Nested
    @DisplayName("Server properties")
    class ServerTests {

        @Test
        @DisplayName("port should default to 443")
        void portShouldDefaultTo443() {
            AtiSdkProperties props = new AtiSdkProperties();

            assertThat(props.getServer().getPort()).isEqualTo(443);
        }

        @Test
        @DisplayName("Should set and get server port")
        void shouldSetAndGetServerPort() {
            AtiSdkProperties props = new AtiSdkProperties();
            props.getServer().setPort(8443);

            assertThat(props.getServer().getPort()).isEqualTo(8443);
        }

        @Test
        @DisplayName("Server certificate should default to null")
        void serverCertificateShouldDefaultToNull() {
            AtiSdkProperties props = new AtiSdkProperties();

            assertThat(props.getServer().getCertificate()).isNull();
            assertThat(props.getServer().getPrivateKey()).isNull();
        }

        @Test
        @DisplayName("Should set and get server certificate and key")
        void shouldSetAndGetServerCertificateAndKey() {
            AtiSdkProperties props = new AtiSdkProperties();
            AtiSdkProperties.Server server = props.getServer();

            server.setCertificate("/path/to/server.crt");
            server.setPrivateKey("/path/to/server.key");

            assertThat(server.getCertificate())
                .isEqualTo("/path/to/server.crt");
            assertThat(server.getPrivateKey())
                .isEqualTo("/path/to/server.key");
        }

        @Test
        @DisplayName("Server verification policy should default to PKI_ONLY")
        void serverVerificationPolicyShouldDefault() {
            AtiSdkProperties props = new AtiSdkProperties();

            assertThat(props.getServer().getVerification().getPolicy())
                .isEqualTo("PKI_ONLY");
        }

        @Test
        @DisplayName("Should set server verification policy")
        void shouldSetServerVerificationPolicy() {
            AtiSdkProperties props = new AtiSdkProperties();
            props.getServer().getVerification().setPolicy("DANE_AND_BADGE");

            assertThat(props.getServer().getVerification().getPolicy())
                .isEqualTo("DANE_AND_BADGE");
        }

        @Test
        @DisplayName("Should replace entire server object")
        void shouldReplaceEntireServerObject() {
            AtiSdkProperties props = new AtiSdkProperties();
            AtiSdkProperties.Server newServer = new AtiSdkProperties.Server();
            newServer.setPort(9443);

            props.setServer(newServer);

            assertThat(props.getServer().getPort()).isEqualTo(9443);
        }

        @Test
        @DisplayName("Should replace server verification object")
        void shouldReplaceServerVerificationObject() {
            AtiSdkProperties props = new AtiSdkProperties();
            AtiSdkProperties.Verification newVerification =
                new AtiSdkProperties.Verification();
            newVerification.setPolicy("PKI_ONLY");

            props.getServer().setVerification(newVerification);

            assertThat(props.getServer().getVerification().getPolicy())
                .isEqualTo("PKI_ONLY");
        }
    }

    // ==================== IDCA Properties ====================

    @Nested
    @DisplayName("IDCA properties")
    class IdcaTests {

        @Test
        @DisplayName("trustCertificate should default to null")
        void trustCertificateShouldDefaultToNull() {
            AtiSdkProperties props = new AtiSdkProperties();

            assertThat(props.getServer().getIdca().getTrustCertificate())
                .isNull();
        }

        @Test
        @DisplayName("Should set and get trustCertificate")
        void shouldSetAndGetTrustCertificate() {
            AtiSdkProperties props = new AtiSdkProperties();
            props.getServer().getIdca()
                .setTrustCertificate("/path/to/idca-trust.pem");

            assertThat(props.getServer().getIdca().getTrustCertificate())
                .isEqualTo("/path/to/idca-trust.pem");
        }

        @Test
        @DisplayName("Should replace entire IDCA object")
        void shouldReplaceEntireIdcaObject() {
            AtiSdkProperties props = new AtiSdkProperties();
            AtiSdkProperties.Idca newIdca = new AtiSdkProperties.Idca();
            newIdca.setTrustCertificate("/new/idca-trust.pem");

            props.getServer().setIdca(newIdca);

            assertThat(props.getServer().getIdca().getTrustCertificate())
                .isEqualTo("/new/idca-trust.pem");
        }
    }

    // ==================== Nested Object Initialization ====================

    @Nested
    @DisplayName("Nested object initialization")
    class NestedObjectInitializationTests {

        @Test
        @DisplayName("All nested objects should be non-null by default")
        void allNestedObjectsShouldBeNonNull() {
            AtiSdkProperties props = new AtiSdkProperties();

            assertThat(props.getDiscovery()).isNotNull();
            assertThat(props.getIdentity()).isNotNull();
            assertThat(props.getServer()).isNotNull();
            assertThat(props.getTransparency()).isNotNull();
            assertThat(props.getVerification()).isNotNull();
            assertThat(props.getClient()).isNotNull();
            assertThat(props.getServer().getVerification()).isNotNull();
            assertThat(props.getServer().getIdca()).isNotNull();
        }
    }
}
