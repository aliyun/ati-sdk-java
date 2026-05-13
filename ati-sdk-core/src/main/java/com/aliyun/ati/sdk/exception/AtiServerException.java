package com.aliyun.ati.sdk.exception;

public class AtiServerException extends AtiException {

    private final int statusCode;

    public AtiServerException(String message) {
        this(message, 500);
    }

    public AtiServerException(String message, int statusCode) {
        super(message);
        this.statusCode = statusCode;
    }

    public AtiServerException(String message, int statusCode, String requestId) {
        super(message, requestId);
        this.statusCode = statusCode;
    }

    public AtiServerException(String message, int statusCode, Throwable cause, String requestId) {
        super(message, cause, requestId);
        this.statusCode = statusCode;
    }

    public int getStatusCode() {
        return statusCode;
    }

    public boolean isRetryable() {
        return statusCode >= 500 && statusCode < 600;
    }
}
