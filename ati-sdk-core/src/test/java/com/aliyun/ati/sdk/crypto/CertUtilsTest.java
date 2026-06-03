package com.aliyun.ati.sdk.crypto;

import java.security.cert.X509Certificate;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class CertUtilsTest {

    @Test
    void shouldComputeSha256Fingerprint() throws Exception {
        byte[] encoded = "test-certificate-bytes".getBytes();
        X509Certificate cert = mock(X509Certificate.class);
        when(cert.getEncoded()).thenReturn(encoded);

        String fingerprint = CertUtils.sha256Fingerprint(cert);

        assertThat(fingerprint).matches("SHA-256:[a-f0-9]{64}");
    }

    @Test
    void shouldReturnConsistentFingerprintForSameInput() throws Exception {
        byte[] encoded = "same-bytes".getBytes();
        X509Certificate cert = mock(X509Certificate.class);
        when(cert.getEncoded()).thenReturn(encoded);

        String first = CertUtils.sha256Fingerprint(cert);
        String second = CertUtils.sha256Fingerprint(cert);

        assertThat(first).isEqualTo(second);
    }

    @Test
    void shouldComputeFingerprintFromRawBytes() {
        byte[] data = "test-data".getBytes();

        String fingerprint = CertUtils.sha256Hex(data);

        assertThat(fingerprint).hasSize(64).matches("[a-f0-9]{64}");
    }

    @Test
    void shouldCompareFingerprintsInConstantTime() throws Exception {
        String a = "SHA-256:abcd1234";
        String b = "SHA-256:abcd1234";
        String c = "SHA-256:different";

        assertThat(CertUtils.fingerprintMatches(a, b)).isTrue();
        assertThat(CertUtils.fingerprintMatches(a, c)).isFalse();
    }

    @Test
    void shouldRejectNullCertificate() {
        assertThatThrownBy(() -> CertUtils.sha256Fingerprint(null))
            .isInstanceOf(NullPointerException.class);
    }
}
