package com.aliyun.ati.sdk.agent.verification;

import java.util.Objects;

public final class VerificationResult {

    public enum Type {
        DANE,
        BADGE,
        PKI_ONLY
    }

    public enum Status {
        SUCCESS,
        MISMATCH,
        NOT_FOUND,
        ERROR
    }

    private final Type type;
    private final Status status;
    private final String detail;

    private VerificationResult(Type type, Status status, String detail) {
        this.type = Objects.requireNonNull(type);
        this.status = Objects.requireNonNull(status);
        this.detail = detail;
    }

    public static VerificationResult success(Type type) {
        return new VerificationResult(type, Status.SUCCESS, null);
    }

    public static VerificationResult failure(Type type, Status status,
                                             String detail) {
        return new VerificationResult(type, status, detail);
    }

    public Type getType() {
        return type;
    }

    public Status getStatus() {
        return status;
    }

    public String getDetail() {
        return detail;
    }

    public boolean isSuccess() {
        return status == Status.SUCCESS;
    }

    @Override
    public String toString() {
        return type + ":" + status
            + (detail != null ? " (" + detail + ")" : "");
    }
}
