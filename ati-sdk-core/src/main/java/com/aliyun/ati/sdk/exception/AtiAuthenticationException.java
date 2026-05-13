package com.aliyun.ati.sdk.exception;

public class AtiAuthenticationException extends AtiException {

    public AtiAuthenticationException(String message) {
        super(message);
    }

    public AtiAuthenticationException(String message, Throwable cause) {
        super(message, cause);
    }

    public AtiAuthenticationException(String message, Throwable cause, String requestId) {
        super(message, cause, requestId);
    }
}
