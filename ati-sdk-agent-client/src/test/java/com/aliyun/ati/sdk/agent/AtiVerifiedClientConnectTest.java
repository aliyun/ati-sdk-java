package com.aliyun.ati.sdk.agent;

import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import com.aliyun.ati.sdk.transparency.TransparencyClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.security.KeyStore;
import java.time.Duration;
import java.util.concurrent.CompletableFuture;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.head;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.lenient;

@ExtendWith(MockitoExtension.class)
class AtiVerifiedClientConnectTest {

    @Mock
    private TransparencyClient mockTransparencyClient;

    @BeforeEach
    void setUp() {
        lenient().when(mockTransparencyClient.getBaseUrl())
            .thenReturn("https://transparency.test.example.com");
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
