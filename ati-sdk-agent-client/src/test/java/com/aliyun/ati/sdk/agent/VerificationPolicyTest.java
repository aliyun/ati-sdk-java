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

    @Test
    void existingPresetsShouldHaveIdcaModeDisabled() {
        assertThat(VerificationPolicy.PKI_ONLY.getIdcaMode())
            .isEqualTo(VerificationMode.DISABLED);
        assertThat(VerificationPolicy.BADGE_REQUIRED.getIdcaMode())
            .isEqualTo(VerificationMode.DISABLED);
        assertThat(VerificationPolicy.DANE_REQUIRED.getIdcaMode())
            .isEqualTo(VerificationMode.DISABLED);
        assertThat(VerificationPolicy.DANE_AND_BADGE.getIdcaMode())
            .isEqualTo(VerificationMode.DISABLED);
    }

    @Test
    void shouldHaveIdcaRequiredWithDaneAndBadgeDisabled() {
        assertThat(VerificationPolicy.IDCA_REQUIRED.getDaneMode())
            .isEqualTo(VerificationMode.DISABLED);
        assertThat(VerificationPolicy.IDCA_REQUIRED.getBadgeMode())
            .isEqualTo(VerificationMode.DISABLED);
        assertThat(VerificationPolicy.IDCA_REQUIRED.getIdcaMode())
            .isEqualTo(VerificationMode.REQUIRED);
    }

    @Test
    void shouldHaveDaneBadgeIdcaAllRequired() {
        assertThat(VerificationPolicy.DANE_BADGE_IDCA.getDaneMode())
            .isEqualTo(VerificationMode.REQUIRED);
        assertThat(VerificationPolicy.DANE_BADGE_IDCA.getBadgeMode())
            .isEqualTo(VerificationMode.REQUIRED);
        assertThat(VerificationPolicy.DANE_BADGE_IDCA.getIdcaMode())
            .isEqualTo(VerificationMode.REQUIRED);
    }

    @Test
    void threeArgConstructorShouldDefaultIdcaToDisabled() {
        VerificationPolicy policy = new VerificationPolicy("TEST",
            VerificationMode.REQUIRED, VerificationMode.ADVISORY);
        assertThat(policy.getIdcaMode()).isEqualTo(VerificationMode.DISABLED);
    }

    @Test
    void fourArgConstructorShouldSetIdcaMode() {
        VerificationPolicy policy = new VerificationPolicy("CUSTOM_IDCA",
            VerificationMode.DISABLED, VerificationMode.REQUIRED,
            VerificationMode.ADVISORY);
        assertThat(policy.getName()).isEqualTo("CUSTOM_IDCA");
        assertThat(policy.getDaneMode()).isEqualTo(VerificationMode.DISABLED);
        assertThat(policy.getBadgeMode()).isEqualTo(VerificationMode.REQUIRED);
        assertThat(policy.getIdcaMode()).isEqualTo(VerificationMode.ADVISORY);
    }
}
