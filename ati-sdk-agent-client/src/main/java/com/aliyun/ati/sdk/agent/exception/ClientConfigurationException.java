package com.aliyun.ati.sdk.agent.exception;

import com.aliyun.ati.sdk.exception.AtiException;

/**
 * Exception thrown when client configuration fails.
 *
 * <p>This exception is thrown during {@link com.aliyun.ati.sdk.agent.AtiVerifiedClient}
 * initialization when configuration issues prevent the client from being built.</p>
 *
 * <p>Common causes include:</p>
 * <ul>
 *   <li>Keystore file not found</li>
 *   <li>Invalid keystore format (not PKCS12/JKS)</li>
 *   <li>Wrong keystore password</li>
 *   <li>SSLContext creation failure</li>
 * </ul>
 */
public class ClientConfigurationException extends AtiException {

    /**
     * Creates a new exception with the specified message.
     *
     * @param message the error message
     */
    public ClientConfigurationException(String message) {
        super(message);
    }

    /**
     * Creates a new exception with the specified message and cause.
     *
     * @param message the error message
     * @param cause the underlying cause
     */
    public ClientConfigurationException(String message, Throwable cause) {
        super(message, cause);
    }
}
