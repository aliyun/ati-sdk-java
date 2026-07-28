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

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Executor;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class ScittVerifierAdapterPostVerifyTest {

    private TransparencyClient mockTransparencyClient;
    private ScittVerifier mockScittVerifier;
    private ScittHeaderProvider mockHeaderProvider;
    private Executor directExecutor;
    private ScittVerifierAdapter adapter;

    @BeforeEach
    void setUp() {
        mockTransparencyClient = mock(TransparencyClient.class);
        when(mockTransparencyClient.getBaseUrl()).thenReturn("https://transparency.test.example.com");
        mockScittVerifier = mock(ScittVerifier.class);
        mockHeaderProvider = mock(ScittHeaderProvider.class);
        directExecutor = Runnable::run;
        adapter = new ScittVerifierAdapter(
            mockTransparencyClient, mockScittVerifier, mockHeaderProvider, directExecutor);
    }

    @Nested
    @DisplayName("postVerify() tests")
    class PostVerifyTests {

        @Test
        @DisplayName("Should reject null hostname")
        void shouldRejectNullHostname() {
            X509Certificate cert = mock(X509Certificate.class);
            ScittPreVerifyResult preResult = ScittPreVerifyResult.notPresent();

            assertThatThrownBy(() -> adapter.postVerify(null, cert, preResult))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("hostname cannot be null");
        }

        @Test
        @DisplayName("Should reject null server certificate")
        void shouldRejectNullServerCert() {
            ScittPreVerifyResult preResult = ScittPreVerifyResult.notPresent();

            assertThatThrownBy(() -> adapter.postVerify("test.example.com", null, preResult))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("serverCert cannot be null");
        }

        @Test
        @DisplayName("Should reject null preResult")
        void shouldRejectNullPreResult() {
            X509Certificate cert = mock(X509Certificate.class);

            assertThatThrownBy(() -> adapter.postVerify("test.example.com", cert, null))
                .isInstanceOf(NullPointerException.class)
                .hasMessageContaining("preResult cannot be null");
        }

        @Test
        @DisplayName("Should return NOT_FOUND when SCITT not present")
        void shouldReturnNotFoundWhenNotPresent() {
            X509Certificate cert = mock(X509Certificate.class);
            ScittPreVerifyResult preResult = ScittPreVerifyResult.notPresent();

            VerificationResult result = adapter.postVerify("test.example.com", cert, preResult);

            assertThat(result.status()).isEqualTo(VerificationResult.Status.NOT_FOUND);
            assertThat(result.type()).isEqualTo(VerificationResult.VerificationType.SCITT);
        }

        @Test
        @DisplayName("Should return ERROR when pre-verification failed")
        void shouldReturnErrorWhenPreVerificationFailed() {
            X509Certificate cert = mock(X509Certificate.class);
            ScittExpectation failedExpectation = ScittExpectation.invalidReceipt("Test failure");
            ScittPreVerifyResult preResult = ScittPreVerifyResult.verified(
                failedExpectation, mock(ScittReceipt.class), mock(StatusToken.class));

            VerificationResult result = adapter.postVerify("test.example.com", cert, preResult);

            assertThat(result.status()).isEqualTo(VerificationResult.Status.ERROR);
            assertThat(result.type()).isEqualTo(VerificationResult.VerificationType.SCITT);
        }

        @Test
        @DisplayName("Should return SUCCESS when post-verification succeeds")
        void shouldReturnSuccessWhenPostVerificationSucceeds() {
            X509Certificate cert = mock(X509Certificate.class);
            ScittExpectation expectation = ScittExpectation.verified(
                List.of("abc123"), List.of(), "ans.test", Map.of(), null);
            ScittPreVerifyResult preResult = ScittPreVerifyResult.verified(
                expectation, mock(ScittReceipt.class), mock(StatusToken.class));

            ScittVerifier.ScittVerificationResult verifyResult =
                ScittVerifier.ScittVerificationResult.success("abc123");
            when(mockScittVerifier.postVerify(any(), any(), any())).thenReturn(verifyResult);

            VerificationResult result = adapter.postVerify("test.example.com", cert, preResult);

            assertThat(result.status()).isEqualTo(VerificationResult.Status.SUCCESS);
            assertThat(result.type()).isEqualTo(VerificationResult.VerificationType.SCITT);
        }

        @Test
        @DisplayName("Should return MISMATCH when post-verification fails")
        void shouldReturnMismatchWhenPostVerificationFails() {
            X509Certificate cert = mock(X509Certificate.class);
            ScittExpectation expectation = ScittExpectation.verified(
                List.of("expected123"), List.of(), "ans.test", Map.of(), null);
            ScittPreVerifyResult preResult = ScittPreVerifyResult.verified(
                expectation, mock(ScittReceipt.class), mock(StatusToken.class));

            ScittVerifier.ScittVerificationResult verifyResult =
                ScittVerifier.ScittVerificationResult.mismatch("actual456", "Mismatch");
            when(mockScittVerifier.postVerify(any(), any(), any())).thenReturn(verifyResult);

            VerificationResult result = adapter.postVerify("test.example.com", cert, preResult);

            assertThat(result.status()).isEqualTo(VerificationResult.Status.MISMATCH);
            assertThat(result.type()).isEqualTo(VerificationResult.VerificationType.SCITT);
        }

        @Test
        @DisplayName("Should return MISMATCH with unknown expected when fingerprints empty")
        void shouldReturnMismatchWithUnknownWhenFingerprintsEmpty() {
            X509Certificate cert = mock(X509Certificate.class);
            ScittExpectation expectation = ScittExpectation.verified(
                List.of(), List.of(), "ans.test", Map.of(), null);
            ScittPreVerifyResult preResult = ScittPreVerifyResult.verified(
                expectation, mock(ScittReceipt.class), mock(StatusToken.class));

            ScittVerifier.ScittVerificationResult verifyResult =
                ScittVerifier.ScittVerificationResult.mismatch("actual456", "No valid fingerprints");
            when(mockScittVerifier.postVerify(any(), any(), any())).thenReturn(verifyResult);

            VerificationResult result = adapter.postVerify("test.example.com", cert, preResult);

            assertThat(result.status()).isEqualTo(VerificationResult.Status.MISMATCH);
            assertThat(result.expectedFingerprint()).isEqualTo("unknown");
        }

        @Test
        @DisplayName("Should return ERROR with default message when failureReason is null")
        void shouldReturnErrorWithDefaultMessageWhenFailureReasonNull() {
            X509Certificate cert = mock(X509Certificate.class);
            // Create expectation with null failureReason
            ScittExpectation failedExpectation = ScittExpectation.keyNotFound(null);
            ScittPreVerifyResult preResult = ScittPreVerifyResult.verified(
                failedExpectation, mock(ScittReceipt.class), mock(StatusToken.class));

            VerificationResult result = adapter.postVerify("test.example.com", cert, preResult);

            assertThat(result.status()).isEqualTo(VerificationResult.Status.ERROR);
            assertThat(result.reason()).contains("SCITT verification failed");
        }
    }
}
