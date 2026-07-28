package com.aliyun.ati.sdk.agent.verification;

import com.aliyun.ati.sdk.transparency.TransparencyClient;
import com.aliyun.ati.sdk.transparency.scitt.ScittExpectation;
import com.aliyun.ati.sdk.transparency.scitt.ScittHeaderProvider;
import com.aliyun.ati.sdk.transparency.scitt.ScittPreVerifyResult;
import com.aliyun.ati.sdk.transparency.scitt.ScittReceipt;
import com.aliyun.ati.sdk.transparency.scitt.ScittVerifier;
import com.aliyun.ati.sdk.transparency.scitt.StatusToken;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.PublicKey;
import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.Executor;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ScittVerifierAdapterTest {

    private TransparencyClient mockTransparencyClient;
    private ScittVerifier mockScittVerifier;
    private ScittHeaderProvider mockHeaderProvider;
    private Executor directExecutor;
    private ScittVerifierAdapter adapter;
    private KeyPair testKeyPair;

    @BeforeEach
    void setUp() throws Exception {
        mockTransparencyClient = mock(TransparencyClient.class);
        when(mockTransparencyClient.getBaseUrl()).thenReturn("https://transparency.test.example.com");
        mockScittVerifier = mock(ScittVerifier.class);
        mockHeaderProvider = mock(ScittHeaderProvider.class);
        directExecutor = Runnable::run; // Synchronous executor for testing

        // Generate test key pair
        testKeyPair = VerificationTestHelpers.generateEcKeyPair();
    }

    /**
     * Helper to convert a PublicKey to a Map keyed by hex key ID.
     */
    private Map<String, PublicKey> toRootKeys(PublicKey publicKey) {
        return VerificationTestHelpers.toRootKeys(publicKey);
    }

    @Nested
    @DisplayName("Constructor tests")
    class ConstructorTests {

        @Test
        @DisplayName("Should create adapter via builder")
        void shouldCreateViaBuilder() {
            ScittVerifierAdapter a = ScittVerifierAdapter.builder()
                .transparencyClient(mockTransparencyClient)
                .build();
            assertThat(a).isNotNull();
        }

        @Test
        @DisplayName("Should reject null transparencyClient in builder")
        void shouldRejectNullTransparencyClient() {
            assertThatThrownBy(() -> ScittVerifierAdapter.builder()
                .transparencyClient(null)
                .build())
                .isInstanceOf(NullPointerException.class);
        }

        @Test
        @DisplayName("Should reject null scittVerifier")
        void shouldRejectNullScittVerifier() {
            assertThatThrownBy(() -> new ScittVerifierAdapter(
                mockTransparencyClient, null, mockHeaderProvider, directExecutor))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("scittVerifier cannot be null");
        }

        @Test
        @DisplayName("Should reject null headerProvider")
        void shouldRejectNullHeaderProvider() {
            assertThatThrownBy(() -> new ScittVerifierAdapter(
                mockTransparencyClient, mockScittVerifier, null, directExecutor))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("headerProvider cannot be null");
        }

        @Test
        @DisplayName("Should reject null executor")
        void shouldRejectNullExecutor() {
            assertThatThrownBy(() -> new ScittVerifierAdapter(
                mockTransparencyClient, mockScittVerifier, mockHeaderProvider, null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("executor cannot be null");
        }
    }

    @Nested
    @DisplayName("Builder tests")
    class BuilderTests {

        @Test
        @DisplayName("Should build adapter with TransparencyClient")
        void shouldBuildWithTransparencyClient() {
            ScittVerifierAdapter a = ScittVerifierAdapter.builder()
                .transparencyClient(mockTransparencyClient)
                .build();
            assertThat(a).isNotNull();
        }

        @Test
        @DisplayName("Should require TransparencyClient in builder")
        void shouldRequireTransparencyClient() {
            assertThatThrownBy(() -> ScittVerifierAdapter.builder().build())
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("transparencyClient is required");
        }

        @Test
        @DisplayName("Should build adapter with custom clock skew tolerance")
        void shouldBuildWithCustomClockSkew() {
            ScittVerifierAdapter a = ScittVerifierAdapter.builder()
                .transparencyClient(mockTransparencyClient)
                .clockSkewTolerance(Duration.ofMinutes(5))
                .build();
            assertThat(a).isNotNull();
        }

        @Test
        @DisplayName("Should build adapter with custom executor")
        void shouldBuildWithCustomExecutor() {
            ScittVerifierAdapter a = ScittVerifierAdapter.builder()
                .transparencyClient(mockTransparencyClient)
                .executor(directExecutor)
                .build();
            assertThat(a).isNotNull();
        }

    }

    @Nested
    @DisplayName("preVerify() tests")
    class PreVerifyTests {

        @BeforeEach
        void setupAdapter() {
            adapter = new ScittVerifierAdapter(
                mockTransparencyClient, mockScittVerifier, mockHeaderProvider, directExecutor);
        }

        @Test
        @DisplayName("Should return notPresent when headers are empty")
        void shouldReturnNotPresentWhenHeadersEmpty() throws Exception {
            when(mockHeaderProvider.extractArtifacts(any())).thenReturn(Optional.empty());

            CompletableFuture<ScittPreVerifyResult> future = adapter.preVerify(Map.of());

            ScittPreVerifyResult result = future.get(5, TimeUnit.SECONDS);
            assertThat(result.isPresent()).isFalse();
        }

        @Test
        @DisplayName("Should return notPresent when artifacts are incomplete")
        void shouldReturnNotPresentWhenIncomplete() throws Exception {
            ScittHeaderProvider.ScittArtifacts incomplete =
                new ScittHeaderProvider.ScittArtifacts(null, null);
            when(mockHeaderProvider.extractArtifacts(any())).thenReturn(Optional.of(incomplete));

            CompletableFuture<ScittPreVerifyResult> future = adapter.preVerify(Map.of());

            ScittPreVerifyResult result = future.get(5, TimeUnit.SECONDS);
            assertThat(result.isPresent()).isFalse();
        }

        @Test
        @DisplayName("Should verify complete artifacts")
        void shouldVerifyCompleteArtifacts() throws Exception {
            ScittReceipt receipt = mock(ScittReceipt.class);
            StatusToken token = mock(StatusToken.class);
            ScittHeaderProvider.ScittArtifacts artifacts =
                new ScittHeaderProvider.ScittArtifacts(receipt, token);

            when(mockHeaderProvider.extractArtifacts(any())).thenReturn(Optional.of(artifacts));
            when(mockTransparencyClient.getRootKeysAsync())
                .thenReturn(CompletableFuture.completedFuture(toRootKeys(testKeyPair.getPublic())));

            ScittExpectation expectation = ScittExpectation.verified(
                List.of("abc123"), List.of(), "ans.test", Map.of(), null);
            when(mockScittVerifier.verify(any(), any(), any())).thenReturn(expectation);

            CompletableFuture<ScittPreVerifyResult> future = adapter.preVerify(Map.of());

            ScittPreVerifyResult result = future.get(5, TimeUnit.SECONDS);
            assertThat(result.isPresent()).isTrue();
            assertThat(result.expectation().isVerified()).isTrue();
        }

        @Test
        @DisplayName("Should return parseError on exception")
        void shouldReturnParseErrorOnException() throws Exception {
            when(mockHeaderProvider.extractArtifacts(any()))
                .thenThrow(new RuntimeException("Parse error"));

            CompletableFuture<ScittPreVerifyResult> future = adapter.preVerify(Map.of());

            ScittPreVerifyResult result = future.get(5, TimeUnit.SECONDS);
            assertThat(result.expectation().status()).isEqualTo(ScittExpectation.Status.PARSE_ERROR);
        }

        @Test
        @DisplayName("Should return parseError on verification exception")
        void shouldReturnParseErrorOnVerificationException() throws Exception {
            ScittReceipt receipt = mock(ScittReceipt.class);
            StatusToken token = mock(StatusToken.class);
            ScittHeaderProvider.ScittArtifacts artifacts =
                new ScittHeaderProvider.ScittArtifacts(receipt, token);

            when(mockHeaderProvider.extractArtifacts(any())).thenReturn(Optional.of(artifacts));
            when(mockTransparencyClient.getRootKeysAsync())
                .thenReturn(CompletableFuture.completedFuture(toRootKeys(testKeyPair.getPublic())));
            when(mockScittVerifier.verify(any(), any(), any()))
                .thenThrow(new RuntimeException("Verification error"));

            CompletableFuture<ScittPreVerifyResult> future = adapter.preVerify(Map.of());

            ScittPreVerifyResult result = future.get(5, TimeUnit.SECONDS);
            assertThat(result.expectation().status()).isEqualTo(ScittExpectation.Status.PARSE_ERROR);
        }

        @Test
        @DisplayName("Should handle async exception via exceptionally")
        void shouldHandleAsyncException() throws Exception {
            ScittReceipt receipt = mock(ScittReceipt.class);
            StatusToken token = mock(StatusToken.class);
            ScittHeaderProvider.ScittArtifacts artifacts =
                new ScittHeaderProvider.ScittArtifacts(receipt, token);

            when(mockHeaderProvider.extractArtifacts(any())).thenReturn(Optional.of(artifacts));
            when(mockTransparencyClient.getRootKeysAsync())
                .thenReturn(CompletableFuture.failedFuture(new RuntimeException("Async failure")));

            CompletableFuture<ScittPreVerifyResult> future = adapter.preVerify(Map.of());

            ScittPreVerifyResult result = future.get(5, TimeUnit.SECONDS);
            assertThat(result.expectation().status()).isEqualTo(ScittExpectation.Status.PARSE_ERROR);
            assertThat(result.expectation().failureReason()).contains("Async failure");
        }

        @Test
        @DisplayName("Should handle key not found with REJECT decision")
        void shouldHandleKeyNotFoundWithReject() throws Exception {
            ScittReceipt receipt = mock(ScittReceipt.class);
            StatusToken token = mock(StatusToken.class);
            when(token.issuedAt()).thenReturn(java.time.Instant.now().minusSeconds(3600));
            ScittHeaderProvider.ScittArtifacts artifacts =
                new ScittHeaderProvider.ScittArtifacts(receipt, token);

            when(mockHeaderProvider.extractArtifacts(any())).thenReturn(Optional.of(artifacts));
            when(mockTransparencyClient.getRootKeysAsync())
                .thenReturn(CompletableFuture.completedFuture(toRootKeys(testKeyPair.getPublic())));

            ScittExpectation keyNotFound = ScittExpectation.keyNotFound("unknown-key-id");
            when(mockScittVerifier.verify(any(), any(), any())).thenReturn(keyNotFound);

            com.aliyun.ati.sdk.transparency.scitt.RefreshDecision rejectDecision =
                com.aliyun.ati.sdk.transparency.scitt.RefreshDecision.reject("Too old");
            when(mockTransparencyClient.refreshRootKeysIfNeeded(any()))
                .thenReturn(CompletableFuture.completedFuture(rejectDecision));

            CompletableFuture<ScittPreVerifyResult> future = adapter.preVerify(Map.of());

            ScittPreVerifyResult result = future.get(5, TimeUnit.SECONDS);
            assertThat(result.expectation().status()).isEqualTo(ScittExpectation.Status.KEY_NOT_FOUND);
        }

        @Test
        @DisplayName("Should handle key not found with DEFER decision")
        void shouldHandleKeyNotFoundWithDefer() throws Exception {
            ScittReceipt receipt = mock(ScittReceipt.class);
            StatusToken token = mock(StatusToken.class);
            when(token.issuedAt()).thenReturn(java.time.Instant.now());
            ScittHeaderProvider.ScittArtifacts artifacts =
                new ScittHeaderProvider.ScittArtifacts(receipt, token);

            when(mockHeaderProvider.extractArtifacts(any())).thenReturn(Optional.of(artifacts));
            when(mockTransparencyClient.getRootKeysAsync())
                .thenReturn(CompletableFuture.completedFuture(toRootKeys(testKeyPair.getPublic())));

            ScittExpectation keyNotFound = ScittExpectation.keyNotFound("unknown-key-id");
            when(mockScittVerifier.verify(any(), any(), any())).thenReturn(keyNotFound);

            com.aliyun.ati.sdk.transparency.scitt.RefreshDecision deferDecision =
                com.aliyun.ati.sdk.transparency.scitt.RefreshDecision.defer("Cooldown active");
            when(mockTransparencyClient.refreshRootKeysIfNeeded(any()))
                .thenReturn(CompletableFuture.completedFuture(deferDecision));

            CompletableFuture<ScittPreVerifyResult> future = adapter.preVerify(Map.of());

            ScittPreVerifyResult result = future.get(5, TimeUnit.SECONDS);
            assertThat(result.expectation().status()).isEqualTo(ScittExpectation.Status.PARSE_ERROR);
        }

        @Test
        @DisplayName("Should handle key not found with REFRESHED decision")
        void shouldHandleKeyNotFoundWithRefreshed() throws Exception {
            ScittReceipt receipt = mock(ScittReceipt.class);
            StatusToken token = mock(StatusToken.class);
            when(token.issuedAt()).thenReturn(java.time.Instant.now());
            ScittHeaderProvider.ScittArtifacts artifacts =
                new ScittHeaderProvider.ScittArtifacts(receipt, token);

            when(mockHeaderProvider.extractArtifacts(any())).thenReturn(Optional.of(artifacts));
            when(mockTransparencyClient.getRootKeysAsync())
                .thenReturn(CompletableFuture.completedFuture(toRootKeys(testKeyPair.getPublic())));

            ScittExpectation keyNotFound = ScittExpectation.keyNotFound("unknown-key-id");
            ScittExpectation verified = ScittExpectation.verified(
                List.of("abc123"), List.of(), "ans.test", Map.of(), null);
            when(mockScittVerifier.verify(any(), any(), any()))
                .thenReturn(keyNotFound)
                .thenReturn(verified);

            Map<String, PublicKey> freshKeys = toRootKeys(testKeyPair.getPublic());
            com.aliyun.ati.sdk.transparency.scitt.RefreshDecision refreshedDecision =
                com.aliyun.ati.sdk.transparency.scitt.RefreshDecision.refreshed(freshKeys);
            when(mockTransparencyClient.refreshRootKeysIfNeeded(any()))
                .thenReturn(CompletableFuture.completedFuture(refreshedDecision));

            CompletableFuture<ScittPreVerifyResult> future = adapter.preVerify(Map.of());

            ScittPreVerifyResult result = future.get(5, TimeUnit.SECONDS);
            assertThat(result.expectation().isVerified()).isTrue();
        }

        @Test
        @DisplayName("Should handle key not found with null issued-at")
        void shouldHandleKeyNotFoundWithNullIssuedAt() throws Exception {
            ScittReceipt receipt = mock(ScittReceipt.class);
            StatusToken token = mock(StatusToken.class);
            when(token.issuedAt()).thenReturn(null);
            when(receipt.protectedHeader()).thenReturn(null);
            ScittHeaderProvider.ScittArtifacts artifacts =
                new ScittHeaderProvider.ScittArtifacts(receipt, token);

            when(mockHeaderProvider.extractArtifacts(any())).thenReturn(Optional.of(artifacts));
            when(mockTransparencyClient.getRootKeysAsync())
                .thenReturn(CompletableFuture.completedFuture(toRootKeys(testKeyPair.getPublic())));

            ScittExpectation keyNotFound = ScittExpectation.keyNotFound("unknown-key-id");
            when(mockScittVerifier.verify(any(), any(), any())).thenReturn(keyNotFound);

            CompletableFuture<ScittPreVerifyResult> future = adapter.preVerify(Map.of());

            ScittPreVerifyResult result = future.get(5, TimeUnit.SECONDS);
            // Should return original key not found since we can't determine artifact time
            assertThat(result.expectation().status()).isEqualTo(ScittExpectation.Status.KEY_NOT_FOUND);
        }
    }

}
