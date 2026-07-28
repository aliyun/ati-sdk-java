package com.aliyun.ati.sdk.agent.verification.crl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.util.Objects;

/**
 * Validates a CRL signature against the issuing CA and checks whether a serial is revoked.
 */
public final class CrlValidator {

    private static final Logger LOGGER = LoggerFactory.getLogger(CrlValidator.class);

    private final CertificateFactory certificateFactory;

    public CrlValidator() {
        this(createCertificateFactory());
    }

    CrlValidator(CertificateFactory certificateFactory) {
        this.certificateFactory = certificateFactory;
    }

    private static CertificateFactory createCertificateFactory() {
        try {
            return CertificateFactory.getInstance("X.509");
        } catch (Exception e) {
            throw new IllegalStateException("Unable to create X.509 CertificateFactory", e);
        }
    }

    /**
     * Parses DER-encoded CRL bytes.
     */
    public X509CRL parse(byte[] crlBytes) throws CrlValidationException {
        Objects.requireNonNull(crlBytes, "crlBytes");
        try {
            return (X509CRL) certificateFactory.generateCRL(new ByteArrayInputStream(crlBytes));
        } catch (Exception e) {
            throw new CrlValidationException("Unable to parse CRL", e);
        }
    }

    /**
     * Verifies the CRL signature using the issuing CA public key.
     */
    public void verifySignature(X509CRL crl, X509Certificate issuingCa) throws CrlValidationException {
        Objects.requireNonNull(crl, "crl");
        Objects.requireNonNull(issuingCa, "issuingCa");
        try {
            crl.verify(issuingCa.getPublicKey());
        } catch (Exception e) {
            throw new CrlValidationException("CRL signature verification failed", e);
        }
    }

    /**
     * Returns {@code true} if the serial appears on the CRL.
     */
    public boolean isSerialRevoked(X509CRL crl, BigInteger serial) {
        Objects.requireNonNull(crl, "crl");
        Objects.requireNonNull(serial, "serial");
        return crl.getRevokedCertificate(serial) != null;
    }

    /**
     * Validates CRL bytes and checks whether the client certificate serial is revoked.
     */
    public void validateNotRevoked(byte[] crlBytes, X509Certificate issuingCa, BigInteger clientSerial)
            throws CrlValidationException {
        X509CRL crl = parse(crlBytes);
        verifySignature(crl, issuingCa);
        if (isSerialRevoked(crl, clientSerial)) {
            LOGGER.debug("Client certificate serial {} is present on CRL", clientSerial);
            throw CrlValidationException.revoked();
        }
    }

    /**
     * Exception thrown when CRL validation fails.
     */
    public static final class CrlValidationException extends Exception {

        private final boolean revoked;

        public CrlValidationException(String message) {
            this(message, null, false);
        }

        public CrlValidationException(String message, Throwable cause) {
            this(message, cause, false);
        }

        private CrlValidationException(String message, Throwable cause, boolean revoked) {
            super(message, cause);
            this.revoked = revoked;
        }

        public static CrlValidationException revoked() {
            return new CrlValidationException("Certificate serial is revoked", null, true);
        }

        public boolean isRevoked() {
            return revoked;
        }
    }
}
