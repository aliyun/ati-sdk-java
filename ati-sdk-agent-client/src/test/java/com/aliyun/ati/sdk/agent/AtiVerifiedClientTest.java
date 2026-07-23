package com.aliyun.ati.sdk.agent;

import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import com.aliyun.ati.sdk.transparency.TransparencyClient;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.io.FileOutputStream;
import java.nio.file.Path;
import java.security.KeyStore;
import java.time.Duration;
import java.util.Map;
import java.util.concurrent.CompletableFuture;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.head;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.lenient;

@ExtendWith(MockitoExtension.class)
class AtiVerifiedClientTest {

    @TempDir
    Path tempDir;

    @Mock
    private TransparencyClient mockTransparencyClient;

    @org.junit.jupiter.api.BeforeEach
    void setUp() {
        lenient().when(mockTransparencyClient.getBaseUrl())
            .thenReturn("https://transparency.test.example.com");
    }

    @Nested
    @DisplayName("Builder tests")
    class BuilderTests {

        @Test
        @DisplayName("Should create client with defaults")
        void shouldCreateClientWithDefaults() throws Exception {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, "password".toCharArray());

            AtiVerifiedClient client = AtiVerifiedClient.builder()
                .keyStore(keyStore, "password".toCharArray())
                .transparencyClient(mockTransparencyClient)
                .build();

            assertThat(client).isNotNull();
            assertThat(client.sslContext()).isNotNull();
            assertThat(client.policy()).isEqualTo(VerificationPolicy.ENHANCED);
            client.close();
        }

        @Test
        @DisplayName("Should use provided policy")
        void shouldUseProvidedPolicy() throws Exception {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, "password".toCharArray());

            AtiVerifiedClient client = AtiVerifiedClient.builder()
                .keyStore(keyStore, "password".toCharArray())
                .transparencyClient(mockTransparencyClient)
                .policy(VerificationPolicy.BASIC)
                .build();

            assertThat(client.policy()).isEqualTo(VerificationPolicy.BASIC);
            client.close();
        }

        @Test
        @DisplayName("Should throw on invalid keystore path")
        void shouldThrowOnInvalidKeystorePath() {
            assertThatThrownBy(() -> AtiVerifiedClient.builder()
                .keyStorePath("/nonexistent/path.p12", "password")
                .transparencyClient(mockTransparencyClient)
                .build())
                .isInstanceOf(RuntimeException.class)
                .hasMessageContaining("Failed to load keystore");
        }

        @Test
        @DisplayName("Should load keystore from path")
        void shouldLoadKeystoreFromPath() throws Exception {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, "testpass".toCharArray());
            Path keystorePath = tempDir.resolve("test.p12");
            try (FileOutputStream fos = new FileOutputStream(keystorePath.toFile())) {
                keyStore.store(fos, "testpass".toCharArray());
            }

            AtiVerifiedClient client = AtiVerifiedClient.builder()
                .keyStorePath(keystorePath.toString(), "testpass")
                .transparencyClient(mockTransparencyClient)
                .build();

            assertThat(client.sslContext()).isNotNull();
            client.close();
        }

        @Test
        @DisplayName("Should set connect timeout")
        void shouldSetConnectTimeout() throws Exception {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, "password".toCharArray());

            AtiVerifiedClient client = AtiVerifiedClient.builder()
                .keyStore(keyStore, "password".toCharArray())
                .transparencyClient(mockTransparencyClient)
                .connectTimeout(Duration.ofSeconds(15))
                .build();

            assertThat(client).isNotNull();
            client.close();
        }

        @Test
        @DisplayName("Should set agent ID")
        void shouldSetAgentId() throws Exception {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, "password".toCharArray());

            AtiVerifiedClient client = AtiVerifiedClient.builder()
                .agentId("test-agent-123")
                .keyStore(keyStore, "password".toCharArray())
                .transparencyClient(mockTransparencyClient)
                .policy(VerificationPolicy.BASIC)
                .build();

            // In simplified policy, SCITT is not enabled so headers are always empty
            assertThat(client.fetchScittHeadersAsync().join()).isEmpty();
            client.close();
        }
    }

    @Nested
    @DisplayName("Accessor tests")
    class AccessorTests {

        @Test
        @DisplayName("transparencyClient() returns the configured client")
        void transparencyClientReturnsConfiguredClient() throws Exception {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, "password".toCharArray());

            AtiVerifiedClient client = AtiVerifiedClient.builder()
                .keyStore(keyStore, "password".toCharArray())
                .transparencyClient(mockTransparencyClient)
                .build();

            assertThat(client.transparencyClient()).isSameAs(mockTransparencyClient);
            client.close();
        }

        @Test
        @DisplayName("fetchScittHeadersAsync() returns empty map (SCITT not in simplified policy)")
        void fetchScittHeadersReturnsEmptyMap() throws Exception {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, "password".toCharArray());

            AtiVerifiedClient client = AtiVerifiedClient.builder()
                .keyStore(keyStore, "password".toCharArray())
                .transparencyClient(mockTransparencyClient)
                .policy(VerificationPolicy.BASIC)
                .build();

            Map<String, String> headers = client.fetchScittHeadersAsync().join();
            assertThat(headers).isEmpty();
            client.close();
        }

        @Test
        @DisplayName("scittHeaders() returns immutable map")
        void scittHeadersReturnsImmutableMap() throws Exception {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, "password".toCharArray());

            AtiVerifiedClient client = AtiVerifiedClient.builder()
                .keyStore(keyStore, "password".toCharArray())
                .transparencyClient(mockTransparencyClient)
                .policy(VerificationPolicy.BASIC)
                .build();

            assertThatThrownBy(() -> client.fetchScittHeadersAsync().join().put("key", "value"))
                .isInstanceOf(UnsupportedOperationException.class);
            client.close();
        }
    }

    @Nested
    @DisplayName("fetchScittHeadersAsync() tests")
    class ScittHeadersAsyncTests {

        @Test
        @DisplayName("Should return completed future with empty map for all policies")
        void shouldReturnCompletedFutureWithEmptyHeaders() throws Exception {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, "password".toCharArray());

            // In the simplified ATI policy, SCITT is never enabled
            for (VerificationPolicy policy : new VerificationPolicy[] {
                VerificationPolicy.BASIC, VerificationPolicy.ENHANCED, VerificationPolicy.ADVANCED
            }) {
                AtiVerifiedClient client = AtiVerifiedClient.builder()
                    .agentId("test-agent")
                    .keyStore(keyStore, "password".toCharArray())
                    .transparencyClient(mockTransparencyClient)
                    .policy(policy)
                    .build();

                CompletableFuture<Map<String, String>> future = client.fetchScittHeadersAsync();
                assertThat(future).isCompletedWithValue(Map.of());
                client.close();
            }
        }

        @Test
        @DisplayName("Should cache headers after first fetch")
        void shouldCacheHeadersAfterFirstFetch() throws Exception {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, "password".toCharArray());

            AtiVerifiedClient client = AtiVerifiedClient.builder()
                .agentId("test-agent")
                .keyStore(keyStore, "password".toCharArray())
                .transparencyClient(mockTransparencyClient)
                .policy(VerificationPolicy.ENHANCED)
                .build();

            // Both calls should return the same cached result
            Map<String, String> headers1 = client.fetchScittHeadersAsync().join();
            Map<String, String> headers2 = client.fetchScittHeadersAsync().join();

            assertThat(headers1).isSameAs(headers2);
            client.close();
        }
    }

    @Nested
    @DisplayName("AutoCloseable tests")
    class AutoCloseableTests {

        @Test
        @DisplayName("Should work in try-with-resources")
        void shouldWorkInTryWithResources() throws Exception {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, "password".toCharArray());

            try (AtiVerifiedClient client = AtiVerifiedClient.builder()
                    .keyStore(keyStore, "password".toCharArray())
                    .transparencyClient(mockTransparencyClient)
                    .build()) {
                assertThat(client).isNotNull();
            }
            // No exception means close() worked
        }
    }

    @Nested
    @DisplayName("TransparencyClient requirement")
    class TransparencyClientRequirementTests {

        @Test
        @DisplayName("Should throw when TransparencyClient not provided")
        void shouldThrowWithoutTransparencyClient() throws Exception {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, "password".toCharArray());

            assertThatThrownBy(() -> AtiVerifiedClient.builder()
                .keyStore(keyStore, "password".toCharArray())
                .policy(VerificationPolicy.BASIC)
                .build())
                .isInstanceOf(IllegalStateException.class)
                .hasMessageContaining("TransparencyClient is required");
        }
    }

    @Nested
    @DisplayName("Verification policy configuration")
    class VerificationPolicyTests {

        @Test
        @DisplayName("BADGE_REQUIRED policy should enable badge verification")
        void badgeRequiredPolicyShouldEnableBadge() throws Exception {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, "password".toCharArray());

            AtiVerifiedClient client = AtiVerifiedClient.builder()
                .keyStore(keyStore, "password".toCharArray())
                .transparencyClient(mockTransparencyClient)
                .policy(VerificationPolicy.ENHANCED)
                .build();

            assertThat(client.policy()).isEqualTo(VerificationPolicy.ENHANCED);
            assertThat(client.policy().hasBadgeVerification()).isTrue();
            assertThat(client.policy().hasDaneVerification()).isFalse();
            client.close();
        }

        @Test
        @DisplayName("DANE_AND_BADGE policy should enable DANE and badge verification")
        void daneAndBadgePolicyShouldEnableBoth() throws Exception {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, "password".toCharArray());

            AtiVerifiedClient client = AtiVerifiedClient.builder()
                .keyStore(keyStore, "password".toCharArray())
                .transparencyClient(mockTransparencyClient)
                .policy(VerificationPolicy.ADVANCED)
                .build();

            assertThat(client.policy()).isEqualTo(VerificationPolicy.ADVANCED);
            assertThat(client.policy().hasDaneVerification()).isTrue();
            assertThat(client.policy().hasBadgeVerification()).isTrue();
            client.close();
        }

        @Test
        @DisplayName("PKI_ONLY policy should have no additional verification")
        void pkiOnlyPolicyShouldHaveNoVerification() throws Exception {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, "password".toCharArray());

            AtiVerifiedClient client = AtiVerifiedClient.builder()
                .keyStore(keyStore, "password".toCharArray())
                .transparencyClient(mockTransparencyClient)
                .policy(VerificationPolicy.BASIC)
                .build();

            assertThat(client.policy()).isEqualTo(VerificationPolicy.BASIC);
            assertThat(client.policy().hasAnyVerification()).isFalse();
            client.close();
        }
    }

    @Nested
    @DisplayName("Agent ID edge cases")
    class AgentIdEdgeCases {

        @Test
        @DisplayName("Should handle blank agent ID gracefully")
        void shouldHandleBlankAgentId() throws Exception {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, "password".toCharArray());

            AtiVerifiedClient client = AtiVerifiedClient.builder()
                .agentId("   ") // Blank
                .keyStore(keyStore, "password".toCharArray())
                .transparencyClient(mockTransparencyClient)
                .policy(VerificationPolicy.ENHANCED)
                .build();

            assertThat(client.fetchScittHeadersAsync().join()).isEmpty();
            client.close();
        }

        @Test
        @DisplayName("Should handle empty agent ID gracefully")
        void shouldHandleEmptyAgentId() throws Exception {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, "password".toCharArray());

            AtiVerifiedClient client = AtiVerifiedClient.builder()
                .agentId("") // Empty
                .keyStore(keyStore, "password".toCharArray())
                .transparencyClient(mockTransparencyClient)
                .policy(VerificationPolicy.ENHANCED)
                .build();

            assertThat(client.fetchScittHeadersAsync().join()).isEmpty();
            client.close();
        }
    }

    @Nested
    @DisplayName("connect() tests")
    @WireMockTest
    class ConnectTests {

        @Test
        @DisplayName("Should connect with PKI_ONLY policy (no preflight)")
        void shouldConnectWithPkiOnly(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, "password".toCharArray());

            AtiVerifiedClient client = AtiVerifiedClient.builder()
                .keyStore(keyStore, "password".toCharArray())
                .transparencyClient(mockTransparencyClient)
                .policy(VerificationPolicy.BASIC)
                .build();

            String serverUrl = wmRuntimeInfo.getHttpBaseUrl() + "/mcp";
            AtiConnection connection = client.connect(serverUrl);

            assertThat(connection).isNotNull();
            assertThat(connection.hostname()).isEqualTo("localhost");
            assertThat(connection.hasScittArtifacts()).isFalse();

            connection.close();
            client.close();
        }

        @Test
        @DisplayName("Should parse URL with custom port")
        void shouldParseUrlWithCustomPort(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
            stubFor(head(urlEqualTo("/api"))
                .willReturn(aResponse().withStatus(200)));

            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, "password".toCharArray());

            AtiVerifiedClient client = AtiVerifiedClient.builder()
                .keyStore(keyStore, "password".toCharArray())
                .transparencyClient(mockTransparencyClient)
                .policy(VerificationPolicy.BASIC)
                .build();

            String serverUrl = wmRuntimeInfo.getHttpBaseUrl() + "/api";
            AtiConnection connection = client.connect(serverUrl);

            assertThat(connection).isNotNull();
            assertThat(connection.hostname()).isEqualTo("localhost");

            connection.close();
            client.close();
        }
    }

    @Nested
    @DisplayName("connectAsync() tests")
    @WireMockTest
    class ConnectAsyncTests {

        @Test
        @DisplayName("Should return completed future with PKI_ONLY policy")
        void shouldReturnCompletedFutureWithPkiOnly(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, "password".toCharArray());

            AtiVerifiedClient client = AtiVerifiedClient.builder()
                .keyStore(keyStore, "password".toCharArray())
                .transparencyClient(mockTransparencyClient)
                .policy(VerificationPolicy.BASIC)
                .build();

            String serverUrl = wmRuntimeInfo.getHttpBaseUrl() + "/mcp";
            CompletableFuture<AtiConnection> future = client.connectAsync(serverUrl);

            assertThat(future).isNotNull();
            assertThat(future).succeedsWithin(Duration.ofSeconds(5));

            AtiConnection connection = future.join();
            assertThat(connection.hostname()).isEqualTo("localhost");
            assertThat(connection.hasScittArtifacts()).isFalse();

            connection.close();
            client.close();
        }

        @Test
        @DisplayName("Should fail future with malformed URL")
        void shouldFailFutureWithMalformedUrl() throws Exception {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, "password".toCharArray());

            AtiVerifiedClient client = AtiVerifiedClient.builder()
                .keyStore(keyStore, "password".toCharArray())
                .transparencyClient(mockTransparencyClient)
                .policy(VerificationPolicy.BASIC)
                .build();

            CompletableFuture<AtiConnection> future = client.connectAsync("not a valid url ://");

            assertThat(future).failsWithin(Duration.ofSeconds(1))
                .withThrowableOfType(java.util.concurrent.ExecutionException.class)
                .withCauseInstanceOf(IllegalArgumentException.class);

            client.close();
        }

        @Test
        @DisplayName("connect() should delegate to connectAsync().join()")
        void connectShouldDelegateToConnectAsync(WireMockRuntimeInfo wmRuntimeInfo) throws Exception {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            keyStore.load(null, "password".toCharArray());

            AtiVerifiedClient client = AtiVerifiedClient.builder()
                .keyStore(keyStore, "password".toCharArray())
                .transparencyClient(mockTransparencyClient)
                .policy(VerificationPolicy.BASIC)
                .build();

            String serverUrl = wmRuntimeInfo.getHttpBaseUrl() + "/api";

            // Both methods should produce equivalent results
            AtiConnection syncConnection = client.connect(serverUrl);
            AtiConnection asyncConnection = client.connectAsync(serverUrl).join();

            assertThat(syncConnection.hostname()).isEqualTo(asyncConnection.hostname());
            assertThat(syncConnection.hasScittArtifacts()).isEqualTo(asyncConnection.hasScittArtifacts());

            syncConnection.close();
            asyncConnection.close();
            client.close();
        }
    }
}
