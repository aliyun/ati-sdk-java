package com.aliyun.ati.sdk.agent;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class VerificationPolicyTest {

    @Test
    void bronzeShouldHaveBothDisabled() {
        assertThat(VerificationPolicy.BRONZE.getDaneMode())
            .isEqualTo(VerificationMode.DISABLED);
        assertThat(VerificationPolicy.BRONZE.getBadgeMode())
            .isEqualTo(VerificationMode.DISABLED);
    }

    @Test
    void silverShouldHaveDaneRequiredBadgeDisabled() {
        assertThat(VerificationPolicy.SILVER.getDaneMode())
            .isEqualTo(VerificationMode.REQUIRED);
        assertThat(VerificationPolicy.SILVER.getBadgeMode())
            .isEqualTo(VerificationMode.DISABLED);
    }

    @Test
    void goldShouldHaveBothRequired() {
        assertThat(VerificationPolicy.GOLD.getDaneMode())
            .isEqualTo(VerificationMode.REQUIRED);
        assertThat(VerificationPolicy.GOLD.getBadgeMode())
            .isEqualTo(VerificationMode.REQUIRED);
    }

    @Test
    void shouldAllowCustomPolicy() {
        VerificationPolicy custom = new VerificationPolicy("CUSTOM",
            VerificationMode.ADVISORY, VerificationMode.REQUIRED);
        assertThat(custom.getName()).isEqualTo("CUSTOM");
        assertThat(custom.getDaneMode()).isEqualTo(VerificationMode.ADVISORY);
        assertThat(custom.getBadgeMode()).isEqualTo(VerificationMode.REQUIRED);
    }

    @Test
    void shouldReturnNameInToString() {
        assertThat(VerificationPolicy.GOLD.toString())
            .isEqualTo("GOLD");
        assertThat(VerificationPolicy.SILVER.toString())
            .isEqualTo("SILVER");
        assertThat(VerificationPolicy.BRONZE.toString())
            .isEqualTo("BRONZE");
    }
}
