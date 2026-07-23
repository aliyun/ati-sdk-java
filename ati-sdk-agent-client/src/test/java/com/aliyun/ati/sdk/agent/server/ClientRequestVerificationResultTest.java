package com.aliyun.ati.sdk.agent.server;

import com.aliyun.ati.sdk.agent.VerificationPolicy;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ClientRequestVerificationResultTest {

    @Nested
    @DisplayName("Constructor validation tests")
    class ConstructorValidationTests {

        @Test
        @DisplayName("Should throw NullPointerException when errors is null")
        void shouldThrowWhenErrorsNull() {
            assertThatThrownBy(() -> new ClientRequestVerificationResult(
                true,
                "agent-123",
                "agent.example.com",
                null,
                VerificationPolicy.ENHANCED,
                Duration.ofMillis(100),
                null, null, null, null
            )).isInstanceOf(NullPointerException.class)
                .hasMessageContaining("errors cannot be null");
        }

        @Test
        @DisplayName("Should throw NullPointerException when policyUsed is null")
        void shouldThrowWhenPolicyNull() {
            assertThatThrownBy(() -> new ClientRequestVerificationResult(
                true,
                "agent-123",
                "agent.example.com",
                List.of(),
                null,
                Duration.ofMillis(100),
                null, null, null, null
            )).isInstanceOf(NullPointerException.class)
                .hasMessageContaining("policyUsed cannot be null");
        }

        @Test
        @DisplayName("Should throw NullPointerException when verificationDuration is null")
        void shouldThrowWhenDurationNull() {
            assertThatThrownBy(() -> new ClientRequestVerificationResult(
                true,
                "agent-123",
                "agent.example.com",
                List.of(),
                VerificationPolicy.ENHANCED,
                null,
                null, null, null, null
            )).isInstanceOf(NullPointerException.class)
                .hasMessageContaining("verificationDuration cannot be null");
        }

        @Test
        @DisplayName("Should create defensive copy of errors list")
        void shouldCreateDefensiveCopyOfErrors() {
            List<String> errors = new ArrayList<>();
            errors.add("error1");

            ClientRequestVerificationResult result = new ClientRequestVerificationResult(
                false,
                null,
                null,
                errors,
                VerificationPolicy.ENHANCED,
                Duration.ofMillis(100),
                null, null, null, null
            );

            // Modify original list
            errors.add("error2");

            // Result should not be affected
            assertThat(result.errors()).containsExactly("error1");
        }

        @Test
        @DisplayName("Should allow null agentId and agentHost")
        void shouldAllowNullAgentIdAndHost() {
            ClientRequestVerificationResult result = new ClientRequestVerificationResult(
                false,
                null,
                null,
                List.of("some error"),
                VerificationPolicy.BASIC,
                Duration.ofMillis(50),
                null, null, null, null
            );

            assertThat(result.agentId()).isNull();
            assertThat(result.agentHost()).isNull();
        }
    }

    @Nested
    @DisplayName("Factory method tests")
    class FactoryMethodTests {

        @Test
        @DisplayName("success() should create verified result")
        void successShouldCreateVerifiedResult() {
            Duration duration = Duration.ofMillis(150);

            ClientRequestVerificationResult result = ClientRequestVerificationResult.success(
                "ati://v1.agent.example.com",
                "agent.example.com",
                VerificationPolicy.ENHANCED,
                duration
            );

            assertThat(result.verified()).isTrue();
            assertThat(result.agentId()).isEqualTo("ati://v1.agent.example.com");
            assertThat(result.agentHost()).isEqualTo("agent.example.com");
            assertThat(result.errors()).isEmpty();
            assertThat(result.policyUsed()).isEqualTo(VerificationPolicy.ENHANCED);
            assertThat(result.verificationDuration()).isEqualTo(duration);
        }

        @Test
        @DisplayName("success() should allow null agentId for PKI_ONLY")
        void successShouldAllowNullAgentIdForPkiOnly() {
            ClientRequestVerificationResult result = ClientRequestVerificationResult.success(
                null,
                "agent.example.com",
                VerificationPolicy.BASIC,
                Duration.ofMillis(10)
            );

            assertThat(result.verified()).isTrue();
            assertThat(result.agentId()).isNull();
            assertThat(result.agentHost()).isEqualTo("agent.example.com");
        }

        @Test
        @DisplayName("failure() with list should create failed result")
        void failureWithListShouldCreateFailedResult() {
            List<String> errors = List.of("error1", "error2");
            Duration duration = Duration.ofMillis(200);

            ClientRequestVerificationResult result = ClientRequestVerificationResult.failure(
                errors,
                "agent.example.com",
                VerificationPolicy.ENHANCED,
                duration
            );

            assertThat(result.verified()).isFalse();
            assertThat(result.agentId()).isNull();
            assertThat(result.agentHost()).isEqualTo("agent.example.com");
            assertThat(result.errors()).containsExactly("error1", "error2");
            assertThat(result.policyUsed()).isEqualTo(VerificationPolicy.ENHANCED);
            assertThat(result.verificationDuration()).isEqualTo(duration);
        }

        @Test
        @DisplayName("failure() with single error should create failed result")
        void failureWithSingleErrorShouldCreateFailedResult() {
            Duration duration = Duration.ofMillis(50);

            ClientRequestVerificationResult result = ClientRequestVerificationResult.failure(
                "Single error message",
                "agent.example.com",
                VerificationPolicy.BASIC,
                duration
            );

            assertThat(result.verified()).isFalse();
            assertThat(result.agentId()).isNull();
            assertThat(result.agentHost()).isEqualTo("agent.example.com");
            assertThat(result.errors()).containsExactly("Single error message");
            assertThat(result.policyUsed()).isEqualTo(VerificationPolicy.BASIC);
            assertThat(result.verificationDuration()).isEqualTo(duration);
        }

        @Test
        @DisplayName("failure() should handle null agentHost")
        void failureShouldHandleNullAgentHost() {
            ClientRequestVerificationResult result = ClientRequestVerificationResult.failure(
                "No ATI SAN found",
                null,
                VerificationPolicy.ENHANCED,
                Duration.ofMillis(100)
            );

            assertThat(result.agentHost()).isNull();
        }
    }

    @Nested
    @DisplayName("toString() tests")
    class ToStringTests {

        @Test
        @DisplayName("toString() for verified result includes agentId and duration")
        void toStringForVerifiedResult() {
            ClientRequestVerificationResult result = ClientRequestVerificationResult.success(
                "ati://v1.test-agent.example.com",
                "test-agent.example.com",
                VerificationPolicy.ENHANCED,
                Duration.ofMillis(123)
            );

            String str = result.toString();

            assertThat(str).contains("verified=true");
            assertThat(str).contains("test-agent.example.com");
            assertThat(str).contains("PT0.123S");
        }

        @Test
        @DisplayName("toString() for failed result includes errors and duration")
        void toStringForFailedResult() {
            ClientRequestVerificationResult result = ClientRequestVerificationResult.failure(
                List.of("error1", "error2"),
                "agent.example.com",
                VerificationPolicy.ENHANCED,
                Duration.ofMillis(456)
            );

            String str = result.toString();

            assertThat(str).contains("verified=false");
            assertThat(str).contains("error1");
            assertThat(str).contains("error2");
            assertThat(str).contains("PT0.456S");
        }
    }
}
