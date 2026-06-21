package com.aliyun.ati.sdk.exception;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for ANS exception hierarchy.
 */
class AtiExceptionTest {

    @Test
    @DisplayName("AtiException should store message and request ID")
    void ansExceptionShouldStoreMessageAndRequestId() {
        AtiException exception = new AtiException("Test error", "req-123");

        assertThat(exception.getMessage()).isEqualTo("Test error");
        assertThat(exception.getRequestId()).isEqualTo("req-123");
    }

    @Test
    @DisplayName("AtiException should store cause")
    void ansExceptionShouldStoreCause() {
        RuntimeException cause = new RuntimeException("Original error");
        AtiException exception = new AtiException("Test error", cause, "req-123");

        assertThat(exception.getCause()).isEqualTo(cause);
    }

    @Test
    @DisplayName("AtiAuthenticationException should store message and request ID")
    void authExceptionShouldStoreMessageAndRequestId() {
        AtiAuthenticationException exception = new AtiAuthenticationException(
            "Auth failed", null, "req-456");

        assertThat(exception.getMessage()).isEqualTo("Auth failed");
        assertThat(exception.getRequestId()).isEqualTo("req-456");
    }

    @Test
    @DisplayName("AtiAuthenticationException should work with simple constructor")
    void authExceptionShouldWorkWithSimpleConstructor() {
        AtiAuthenticationException exception = new AtiAuthenticationException("Auth failed");

        assertThat(exception.getMessage()).isEqualTo("Auth failed");
    }

    @Test
    @DisplayName("AtiNotFoundException should store resource information")
    void notFoundExceptionShouldStoreResourceInfo() {
        AtiNotFoundException exception = new AtiNotFoundException(
            "Agent not found", "agent", "agent-123", "req-789");

        assertThat(exception.getMessage()).isEqualTo("Agent not found");
        assertThat(exception.getResourceType()).isEqualTo("agent");
        assertThat(exception.getResourceId()).isEqualTo("agent-123");
        assertThat(exception.getRequestId()).isEqualTo("req-789");
    }

    @Test
    @DisplayName("AtiValidationException should store field errors")
    void validationExceptionShouldStoreErrors() {
        Map<String, String> errors = Map.of(
            "agentHost", "must not be blank",
            "version", "invalid semver"
        );

        AtiValidationException exception = new AtiValidationException(
            "Validation failed", errors, "req-101");

        assertThat(exception.getMessage()).isEqualTo("Validation failed");
        assertThat(exception.getFieldErrors()).containsKey("agentHost");
        assertThat(exception.getFieldErrors().get("agentHost")).isEqualTo("must not be blank");
        assertThat(exception.getFieldErrors().get("version")).isEqualTo("invalid semver");
    }

    @Test
    @DisplayName("AtiValidationException should handle null errors")
    void validationExceptionShouldHandleNullErrors() {
        AtiValidationException exception = new AtiValidationException(
            "Validation failed", null, "req-102");

        assertThat(exception.getFieldErrors()).isEmpty();
    }

    @Test
    @DisplayName("AtiValidationException should work with simple constructor")
    void validationExceptionShouldWorkWithSimpleConstructor() {
        AtiValidationException exception = new AtiValidationException("Validation failed");

        assertThat(exception.getMessage()).isEqualTo("Validation failed");
        assertThat(exception.getFieldErrors()).isEmpty();
    }

    @Test
    @DisplayName("AtiServerException should store status code")
    void serverExceptionShouldStoreStatusCode() {
        AtiServerException exception = new AtiServerException(
            "Internal server error", 500, "req-500");

        assertThat(exception.getMessage()).isEqualTo("Internal server error");
        assertThat(exception.getStatusCode()).isEqualTo(500);
        assertThat(exception.getRequestId()).isEqualTo("req-500");
    }

    @Test
    @DisplayName("AtiServerException should store cause")
    void serverExceptionShouldStoreCause() {
        RuntimeException cause = new RuntimeException("Network error");
        AtiServerException exception = new AtiServerException(
            "Server error", 502, cause, "req-502");

        assertThat(exception.getCause()).isEqualTo(cause);
        assertThat(exception.getStatusCode()).isEqualTo(502);
    }

    @Test
    @DisplayName("All exceptions should extend AtiException")
    void allExceptionsShouldExtendAtiException() {
        assertThat(new AtiAuthenticationException("msg"))
            .isInstanceOf(AtiException.class);
        assertThat(new AtiNotFoundException("msg", null, null, null))
            .isInstanceOf(AtiException.class);
        assertThat(new AtiValidationException("msg"))
            .isInstanceOf(AtiException.class);
        assertThat(new AtiServerException("msg", 500, null))
            .isInstanceOf(AtiException.class);
    }

    @Test
    @DisplayName("All exceptions should extend RuntimeException")
    void allExceptionsShouldExtendRuntimeException() {
        assertThat(new AtiException("msg", "req"))
            .isInstanceOf(RuntimeException.class);
    }

    @Test
    @DisplayName("AtiConflictException should store message")
    void conflictExceptionShouldStoreMessage() {
        AtiConflictException exception = new AtiConflictException("Resource already exists");

        assertThat(exception.getMessage()).isEqualTo("Resource already exists");
    }

    @Test
    @DisplayName("AtiConflictException should store message and request ID")
    void conflictExceptionShouldStoreMessageAndRequestId() {
        AtiConflictException exception = new AtiConflictException(
            "Agent already registered", "req-409");

        assertThat(exception.getMessage()).isEqualTo("Agent already registered");
        assertThat(exception.getRequestId()).isEqualTo("req-409");
    }

    @Test
    @DisplayName("AtiConflictException should extend AtiException")
    void conflictExceptionShouldExtendAtiException() {
        assertThat(new AtiConflictException("msg"))
            .isInstanceOf(AtiException.class);
    }

    @Test
    @DisplayName("AtiValidationException with field errors via two-arg constructor")
    void validationExceptionTwoArgConstructorWithFieldErrors() {
        Map<String, String> errors = Map.of("field1", "error1");
        AtiValidationException exception = new AtiValidationException("Validation failed", errors);

        assertThat(exception.getMessage()).isEqualTo("Validation failed");
        assertThat(exception.getFieldErrors()).containsEntry("field1", "error1");
    }

    @Test
    @DisplayName("AtiNotFoundException simple constructor")
    void notFoundExceptionSimpleConstructor() {
        AtiNotFoundException exception = new AtiNotFoundException(
            "Not found", "type", "id", null);

        assertThat(exception.getMessage()).isEqualTo("Not found");
        assertThat(exception.getResourceType()).isEqualTo("type");
        assertThat(exception.getResourceId()).isEqualTo("id");
        assertThat(exception.getRequestId()).isNull();
    }

    // Additional tests for full coverage

    @Test
    @DisplayName("AtiException message-only constructor")
    void ansExceptionMessageOnlyConstructor() {
        AtiException exception = new AtiException("Simple error");

        assertThat(exception.getMessage()).isEqualTo("Simple error");
        assertThat(exception.getRequestId()).isNull();
        assertThat(exception.getCause()).isNull();
    }

    @Test
    @DisplayName("AtiException message and cause constructor")
    void ansExceptionMessageAndCauseConstructor() {
        RuntimeException cause = new RuntimeException("Root cause");
        AtiException exception = new AtiException("Error with cause", cause);

        assertThat(exception.getMessage()).isEqualTo("Error with cause");
        assertThat(exception.getCause()).isEqualTo(cause);
        assertThat(exception.getRequestId()).isNull();
    }

    @Test
    @DisplayName("AtiNotFoundException single-arg constructor")
    void notFoundExceptionSingleArgConstructor() {
        AtiNotFoundException exception = new AtiNotFoundException("Resource not found");

        assertThat(exception.getMessage()).isEqualTo("Resource not found");
        assertThat(exception.getResourceType()).isNull();
        assertThat(exception.getResourceId()).isNull();
    }

    @Test
    @DisplayName("AtiNotFoundException two-arg constructor creates message from resource")
    void notFoundExceptionTwoArgConstructor() {
        AtiNotFoundException exception = new AtiNotFoundException("Agent", "agent-xyz");

        assertThat(exception.getMessage()).isEqualTo("Agent not found: agent-xyz");
        assertThat(exception.getResourceType()).isEqualTo("Agent");
        assertThat(exception.getResourceId()).isEqualTo("agent-xyz");
    }

    @Test
    @DisplayName("AtiNotFoundException three-arg constructor")
    void notFoundExceptionThreeArgConstructor() {
        AtiNotFoundException exception = new AtiNotFoundException(
            "Custom message", "Resource", "res-123");

        assertThat(exception.getMessage()).isEqualTo("Custom message");
        assertThat(exception.getResourceType()).isEqualTo("Resource");
        assertThat(exception.getResourceId()).isEqualTo("res-123");
        assertThat(exception.getRequestId()).isNull();
    }

    @Test
    @DisplayName("AtiNotFoundException getAgentId returns ID for Agent type")
    void notFoundExceptionGetAgentIdForAgentType() {
        AtiNotFoundException exception = new AtiNotFoundException("Agent", "agent-456");

        assertThat(exception.getAgentId()).isEqualTo("agent-456");
    }

    @Test
    @DisplayName("AtiNotFoundException getAgentId returns null for non-Agent type")
    void notFoundExceptionGetAgentIdForNonAgentType() {
        AtiNotFoundException exception = new AtiNotFoundException("Service", "svc-789");

        assertThat(exception.getAgentId()).isNull();
    }

    @Test
    @DisplayName("AtiServerException single-arg constructor defaults to 500")
    void serverExceptionSingleArgConstructor() {
        AtiServerException exception = new AtiServerException("Server error");

        assertThat(exception.getMessage()).isEqualTo("Server error");
        assertThat(exception.getStatusCode()).isEqualTo(500);
    }

    @Test
    @DisplayName("AtiServerException two-arg constructor")
    void serverExceptionTwoArgConstructor() {
        AtiServerException exception = new AtiServerException("Bad gateway", 502);

        assertThat(exception.getMessage()).isEqualTo("Bad gateway");
        assertThat(exception.getStatusCode()).isEqualTo(502);
        assertThat(exception.getRequestId()).isNull();
    }

    @Test
    @DisplayName("AtiServerException getCode alias method")
    void serverExceptionGetCodeAlias() {
        AtiServerException exception = new AtiServerException("Error", 503);

        assertThat(exception.getCode()).isEqualTo(503);
        assertThat(exception.getCode()).isEqualTo(exception.getStatusCode());
    }

    @Test
    @DisplayName("AtiServerException isRetryable returns true for 5xx status")
    void serverExceptionIsRetryableFor5xx() {
        assertThat(new AtiServerException("Error", 500).isRetryable()).isTrue();
        assertThat(new AtiServerException("Error", 502).isRetryable()).isTrue();
        assertThat(new AtiServerException("Error", 503).isRetryable()).isTrue();
        assertThat(new AtiServerException("Error", 599).isRetryable()).isTrue();
    }

    @Test
    @DisplayName("AtiServerException isRetryable returns false for non-5xx status")
    void serverExceptionIsRetryableForNon5xx() {
        assertThat(new AtiServerException("Error", 400).isRetryable()).isFalse();
        assertThat(new AtiServerException("Error", 404).isRetryable()).isFalse();
        assertThat(new AtiServerException("Error", 499).isRetryable()).isFalse();
        assertThat(new AtiServerException("Error", 600).isRetryable()).isFalse();
    }

    @Test
    @DisplayName("AtiAuthenticationException with message and cause")
    void authExceptionMessageAndCauseConstructor() {
        RuntimeException cause = new RuntimeException("Token expired");
        AtiAuthenticationException exception = new AtiAuthenticationException(
            "Authentication failed", cause);

        assertThat(exception.getMessage()).isEqualTo("Authentication failed");
        assertThat(exception.getCause()).isEqualTo(cause);
        assertThat(exception.getRequestId()).isNull();
    }
}