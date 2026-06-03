package com.aliyun.ati.sdk.agent;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class VerificationPolicyTest {

    @Test
    void shouldHavePkiOnlyWithBothDisabled() {
        assertThat(VerificationPolicy.PKI_ONLY.getDaneMode())
            .isEqualTo(VerificationMode.DISABLED);
        assertThat(VerificationPolicy.PKI_ONLY.getBadgeMode())
            .isEqualTo(VerificationMode.DISABLED);
    }

    @Test
    void shouldHaveBadgeRequiredWithDaneDisabled() {
        assertThat(VerificationPolicy.BADGE_REQUIRED.getDaneMode())
            .isEqualTo(VerificationMode.DISABLED);
        assertThat(VerificationPolicy.BADGE_REQUIRED.getBadgeMode())
            .isEqualTo(VerificationMode.REQUIRED);
    }

    @Test
    void shouldHaveDaneRequiredWithBadgeDisabled() {
        assertThat(VerificationPolicy.DANE_REQUIRED.getDaneMode())
            .isEqualTo(VerificationMode.REQUIRED);
        assertThat(VerificationPolicy.DANE_REQUIRED.getBadgeMode())
            .isEqualTo(VerificationMode.DISABLED);
    }

    @Test
    void shouldHaveDaneAndBadgeBothRequired() {
        assertThat(VerificationPolicy.DANE_AND_BADGE.getDaneMode())
            .isEqualTo(VerificationMode.REQUIRED);
        assertThat(VerificationPolicy.DANE_AND_BADGE.getBadgeMode())
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
        assertThat(VerificationPolicy.DANE_AND_BADGE.toString())
            .isEqualTo("DANE_AND_BADGE");
    }
}
