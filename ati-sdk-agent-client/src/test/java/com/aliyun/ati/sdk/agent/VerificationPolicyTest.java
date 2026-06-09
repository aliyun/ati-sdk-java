package com.aliyun.ati.sdk.agent;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class VerificationPolicyTest {

    @Test
    void shouldHaveThreeLevels() {
        assertThat(VerificationPolicy.values()).hasSize(3);
        assertThat(VerificationPolicy.BRONZE.ordinal()).isEqualTo(0);
        assertThat(VerificationPolicy.SILVER.ordinal()).isEqualTo(1);
        assertThat(VerificationPolicy.GOLD.ordinal()).isEqualTo(2);
    }

    @Test
    void shouldReturnNameInToString() {
        assertThat(VerificationPolicy.GOLD.toString()).isEqualTo("GOLD");
        assertThat(VerificationPolicy.SILVER.toString()).isEqualTo("SILVER");
        assertThat(VerificationPolicy.BRONZE.toString()).isEqualTo("BRONZE");
    }

    @Test
    void shouldParseFromString() {
        assertThat(VerificationPolicy.valueOf("GOLD"))
            .isEqualTo(VerificationPolicy.GOLD);
        assertThat(VerificationPolicy.valueOf("SILVER"))
            .isEqualTo(VerificationPolicy.SILVER);
        assertThat(VerificationPolicy.valueOf("BRONZE"))
            .isEqualTo(VerificationPolicy.BRONZE);
    }
}
