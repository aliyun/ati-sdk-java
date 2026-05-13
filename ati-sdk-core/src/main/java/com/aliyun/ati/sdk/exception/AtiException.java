package com.aliyun.ati.sdk.exception;

public class AtiException extends RuntimeException {

    private final String requestId;

    public AtiException(String message) {
        this(message, null, null);
    }

    public AtiException(String message, Throwable cause) {
        this(message, cause, null);
    }

    public AtiException(String message, String requestId) {
        this(message, null, requestId);
    }

    public AtiException(String message, Throwable cause, String requestId) {
        super(message, cause);
        this.requestId = requestId;
    }

    public String getRequestId() {
        return requestId;
    }
}
