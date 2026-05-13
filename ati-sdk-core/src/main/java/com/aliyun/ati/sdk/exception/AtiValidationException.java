package com.aliyun.ati.sdk.exception;

public class AtiValidationException extends AtiException {

    public AtiValidationException(String message) {
        super(message);
    }

    public AtiValidationException(String message, String requestId) {
        super(message, requestId);
    }

    public AtiValidationException(String message, Throwable cause, String requestId) {
        super(message, cause, requestId);
    }
}
