package com.aliyun.ati.sdk.exception;

public class AtiNotFoundException extends AtiException {

    public AtiNotFoundException(String message) {
        super(message);
    }

    public AtiNotFoundException(String message, String requestId) {
        super(message, requestId);
    }

    public AtiNotFoundException(String message, Throwable cause, String requestId) {
        super(message, cause, requestId);
    }
}
