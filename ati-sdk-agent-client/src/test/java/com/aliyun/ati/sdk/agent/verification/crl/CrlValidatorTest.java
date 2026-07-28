package com.aliyun.ati.sdk.agent.verification.crl;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("CrlValidator")
class CrlValidatorTest {

    private CrlTestFixtures.TestCa ca;
    private CrlValidator validator;

    @BeforeEach
    void setUp() throws Exception {
        ca = CrlTestFixtures.createTestCa();
        validator = new CrlValidator();
    }

    @Test
    @DisplayName("detects revoked serial on CRL")
    void detectsRevokedSerial() throws Exception {
        BigInteger revokedSerial = BigInteger.valueOf(1001);
        byte[] crlBytes = CrlTestFixtures.createCrlBytes(
            ca,
            Instant.now().plus(1, ChronoUnit.DAYS),
            Set.of(revokedSerial)
        );

        assertThatThrownBy(() -> validator.validateNotRevoked(crlBytes, ca.certificate(), revokedSerial))
            .isInstanceOf(CrlValidator.CrlValidationException.class)
            .matches(e -> ((CrlValidator.CrlValidationException) e).isRevoked());
    }

    @Test
    @DisplayName("passes when serial is not on CRL")
    void passesWhenSerialNotRevoked() throws Exception {
        BigInteger revokedSerial = BigInteger.valueOf(1001);
        BigInteger cleanSerial = BigInteger.valueOf(2002);
        byte[] crlBytes = CrlTestFixtures.createCrlBytes(
            ca,
            Instant.now().plus(1, ChronoUnit.DAYS),
            Set.of(revokedSerial)
        );

        validator.validateNotRevoked(crlBytes, ca.certificate(), cleanSerial);
    }

    @Test
    @DisplayName("rejects CRL with invalid signature")
    void rejectsInvalidSignature() throws Exception {
        CrlTestFixtures.TestCa otherCa = CrlTestFixtures.createTestCa("http://crl.example.test/other.crl");
        byte[] crlBytes = CrlTestFixtures.createCrlBytes(
            otherCa,
            Instant.now().plus(1, ChronoUnit.DAYS),
            Set.of()
        );

        assertThatThrownBy(() -> validator.validateNotRevoked(crlBytes, ca.certificate(), BigInteger.ONE))
            .isInstanceOf(CrlValidator.CrlValidationException.class)
            .hasMessageContaining("signature");
    }

    @Test
    @DisplayName("rejects unparsable CRL bytes")
    void rejectsUnparsableCrl() {
        assertThatThrownBy(() -> validator.parse(new byte[] { 1, 2, 3 }))
            .isInstanceOf(CrlValidator.CrlValidationException.class)
            .hasMessageContaining("Unable to parse CRL")
            .matches(e -> !((CrlValidator.CrlValidationException) e).isRevoked());
    }

    @Test
    @DisplayName("verifySignature rejects CRL signed by another CA")
    void verifySignatureRejectsWrongSigner() throws Exception {
        CrlTestFixtures.TestCa otherCa = CrlTestFixtures.createTestCa("http://crl.example.test/other.crl");
        byte[] crlBytes = CrlTestFixtures.createCrlBytes(
            otherCa,
            Instant.now().plus(1, ChronoUnit.DAYS),
            Set.of()
        );
        var crl = validator.parse(crlBytes);

        assertThatThrownBy(() -> validator.verifySignature(crl, ca.certificate()))
            .isInstanceOf(CrlValidator.CrlValidationException.class)
            .hasMessageContaining("signature")
            .matches(e -> !((CrlValidator.CrlValidationException) e).isRevoked());
    }

    @Test
    @DisplayName("isSerialRevoked detects revoked entries")
    void isSerialRevokedDetectsRevokedEntry() throws Exception {
        BigInteger revokedSerial = BigInteger.valueOf(3001);
        byte[] crlBytes = CrlTestFixtures.createCrlBytes(
            ca,
            Instant.now().plus(1, ChronoUnit.DAYS),
            Set.of(revokedSerial)
        );
        var crl = validator.parse(crlBytes);

        assertThat(validator.isSerialRevoked(crl, revokedSerial)).isTrue();
        assertThat(validator.isSerialRevoked(crl, BigInteger.valueOf(3002))).isFalse();
    }
}
