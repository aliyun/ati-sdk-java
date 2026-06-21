package com.aliyun.ati.sdk.agent.exception;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;

/**
 * Tests for ClientConfigurationException.
 */
class ClientConfigurationExceptionTest {

    @Test
    void constructorWithMessageOnly() {
        ClientConfigurationException ex = new ClientConfigurationException("Failed to load keystore");

        assertEquals("Failed to load keystore", ex.getMessage());
        assertNull(ex.getCause());
    }

    @Test
    void constructorWithMessageAndCause() {
        RuntimeException cause = new RuntimeException("Wrong password");
        ClientConfigurationException ex = new ClientConfigurationException("Failed to load keystore", cause);

        assertEquals("Failed to load keystore", ex.getMessage());
        assertSame(cause, ex.getCause());
    }

    @Test
    void extendsAtiException() {
        ClientConfigurationException ex = new ClientConfigurationException("Config error");

        assertEquals(com.aliyun.ati.sdk.exception.AtiException.class, ex.getClass().getSuperclass());
    }
}
