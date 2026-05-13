package com.aliyun.ati.sdk.exception;

public class AtiConflictException extends AtiException {

    public AtiConflictException(String message) {
        super(message);
    }

    public AtiConflictException(String message, String requestId) {
        super(message, requestId);
    }

    public AtiConflictException(String message, Throwable cause, String requestId) {
        super(message, cause, requestId);
    }
}
