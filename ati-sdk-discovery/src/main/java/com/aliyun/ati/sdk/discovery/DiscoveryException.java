package com.aliyun.ati.sdk.discovery;

import com.aliyun.ati.sdk.exception.AtiException;

/**
 * Exception thrown when DNS-based agent discovery fails.
 */
public class DiscoveryException extends AtiException {

    public DiscoveryException(String message) {
        super(message);
    }

    public DiscoveryException(String message, Throwable cause) {
        super(message, cause);
    }
}
