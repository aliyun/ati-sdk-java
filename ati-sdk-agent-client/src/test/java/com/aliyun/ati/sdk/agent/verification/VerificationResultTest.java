package com.aliyun.ati.sdk.agent.verification;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class VerificationResultTest {

    @Test
    void shouldCreateSuccessResult() {
        VerificationResult result =
            VerificationResult.success(VerificationResult.Type.DANE);

        assertThat(result.isSuccess()).isTrue();
        assertThat(result.getType()).isEqualTo(VerificationResult.Type.DANE);
        assertThat(result.getStatus())
            .isEqualTo(VerificationResult.Status.SUCCESS);
        assertThat(result.getDetail()).isNull();
    }

    @Test
    void shouldCreateFailureResult() {
        VerificationResult result = VerificationResult.failure(
            VerificationResult.Type.BADGE,
            VerificationResult.Status.MISMATCH,
            "fingerprint mismatch");

        assertThat(result.isSuccess()).isFalse();
        assertThat(result.getType()).isEqualTo(VerificationResult.Type.BADGE);
        assertThat(result.getStatus())
            .isEqualTo(VerificationResult.Status.MISMATCH);
        assertThat(result.getDetail()).isEqualTo("fingerprint mismatch");
    }

    @Test
    void shouldFormatToStringWithoutDetail() {
        VerificationResult result =
            VerificationResult.success(VerificationResult.Type.PKI_ONLY);

        assertThat(result.toString()).isEqualTo("PKI_ONLY:SUCCESS");
    }

    @Test
    void shouldFormatToStringWithDetail() {
        VerificationResult result = VerificationResult.failure(
            VerificationResult.Type.DANE,
            VerificationResult.Status.ERROR,
            "timeout");

        assertThat(result.toString()).isEqualTo("DANE:ERROR (timeout)");
    }
}
