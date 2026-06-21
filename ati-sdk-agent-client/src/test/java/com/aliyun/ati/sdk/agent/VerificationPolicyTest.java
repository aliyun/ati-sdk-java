package com.aliyun.ati.sdk.agent;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for VerificationPolicy enum.
 */
class VerificationPolicyTest {

    @Test
    void enumHasThreeValues() {
        assertEquals(3, VerificationPolicy.values().length);
    }

    @Test
    void pkiOnlyHasNoVerification() {
        assertFalse(VerificationPolicy.PKI_ONLY.hasAnyVerification());
        assertFalse(VerificationPolicy.PKI_ONLY.hasBadgeVerification());
        assertFalse(VerificationPolicy.PKI_ONLY.hasDaneVerification());
    }

    @Test
    void badgeRequiredHasBadgeOnly() {
        assertTrue(VerificationPolicy.BADGE_REQUIRED.hasAnyVerification());
        assertTrue(VerificationPolicy.BADGE_REQUIRED.hasBadgeVerification());
        assertFalse(VerificationPolicy.BADGE_REQUIRED.hasDaneVerification());
    }

    @Test
    void daneAndBadgeHasBothVerifications() {
        assertTrue(VerificationPolicy.DANE_AND_BADGE.hasAnyVerification());
        assertTrue(VerificationPolicy.DANE_AND_BADGE.hasBadgeVerification());
        assertTrue(VerificationPolicy.DANE_AND_BADGE.hasDaneVerification());
    }

    @Test
    void ordinalValues() {
        assertEquals(0, VerificationPolicy.PKI_ONLY.ordinal());
        assertEquals(1, VerificationPolicy.BADGE_REQUIRED.ordinal());
        assertEquals(2, VerificationPolicy.DANE_AND_BADGE.ordinal());
    }

    @Test
    void allValuesAreNotNull() {
        for (VerificationPolicy policy : VerificationPolicy.values()) {
            assertNotNull(policy);
            assertNotNull(policy.name());
        }
    }

    @Test
    void valueOfWorks() {
        assertEquals(VerificationPolicy.PKI_ONLY, VerificationPolicy.valueOf("PKI_ONLY"));
        assertEquals(VerificationPolicy.BADGE_REQUIRED, VerificationPolicy.valueOf("BADGE_REQUIRED"));
        assertEquals(VerificationPolicy.DANE_AND_BADGE, VerificationPolicy.valueOf("DANE_AND_BADGE"));
    }

    @Test
    void hasBadgeVerificationIsProgressive() {
        // PKI_ONLY (ordinal 0) -> no badge
        assertFalse(VerificationPolicy.PKI_ONLY.hasBadgeVerification());
        // BADGE_REQUIRED (ordinal 1) -> has badge
        assertTrue(VerificationPolicy.BADGE_REQUIRED.hasBadgeVerification());
        // DANE_AND_BADGE (ordinal 2) -> has badge (includes all from lower levels)
        assertTrue(VerificationPolicy.DANE_AND_BADGE.hasBadgeVerification());
    }

    @Test
    void hasDaneVerificationOnlyAtHighestLevel() {
        assertFalse(VerificationPolicy.PKI_ONLY.hasDaneVerification());
        assertFalse(VerificationPolicy.BADGE_REQUIRED.hasDaneVerification());
        assertTrue(VerificationPolicy.DANE_AND_BADGE.hasDaneVerification());
    }
}
