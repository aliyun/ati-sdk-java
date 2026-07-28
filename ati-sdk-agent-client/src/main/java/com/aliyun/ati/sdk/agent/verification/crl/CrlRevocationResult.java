package com.aliyun.ati.sdk.agent.verification.crl;

import java.net.URI;
import java.util.Objects;
import java.util.Optional;

/**
 * Result of a Certificate Revocation List (CRL) check against a client Identity Certificate.
 */
public final class CrlRevocationResult {

    /**
     * Outcome of the CRL revocation check.
     */
    public enum Status {
        /** No CDP on the certificate chain; CRL check was skipped. */
        SKIPPED,
        /** Client certificate serial is not on the CRL. */
        PASSED,
        /** Client certificate serial appears on the CRL (Certificate Revocation). */
        REVOKED,
        /** CDP was present but fetch, parse, or signature validation failed (fail-closed). */
        FAILED
    }

    private final Status status;
    private final String message;
    private final URI cdpUri;

    private CrlRevocationResult(Status status, String message, URI cdpUri) {
        this.status = Objects.requireNonNull(status, "status");
        this.message = message;
        this.cdpUri = cdpUri;
    }

    public static CrlRevocationResult skipped() {
        return new CrlRevocationResult(Status.SKIPPED, null, null);
    }

    public static CrlRevocationResult passed(URI cdpUri) {
        return new CrlRevocationResult(Status.PASSED, null, cdpUri);
    }

    public static CrlRevocationResult revoked(URI cdpUri) {
        return new CrlRevocationResult(Status.REVOKED, "Certificate serial is revoked", cdpUri);
    }

    public static CrlRevocationResult failed(String message, URI cdpUri) {
        return new CrlRevocationResult(Status.FAILED, message, cdpUri);
    }

    public Status status() {
        return status;
    }

    public Optional<String> message() {
        return Optional.ofNullable(message);
    }

    public Optional<URI> cdpUri() {
        return Optional.ofNullable(cdpUri);
    }

    public boolean isSkipped() {
        return status == Status.SKIPPED;
    }

    public boolean isPassed() {
        return status == Status.PASSED;
    }

    public boolean isRevoked() {
        return status == Status.REVOKED;
    }

    public boolean isFailed() {
        return status == Status.FAILED;
    }

    public boolean shouldRejectConnection() {
        return status == Status.REVOKED || status == Status.FAILED;
    }
}
