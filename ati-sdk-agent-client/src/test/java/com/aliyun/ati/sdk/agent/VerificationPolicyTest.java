package com.aliyun.ati.sdk.agent;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Tests for VerificationPolicy enum.
 */
class VerificationPolicyTest {

    @Test
    void enumHasFourValues() {
        assertEquals(4, VerificationPolicy.values().length);
    }

    @Test
    void noneSkipsAllVerification() {
        assertFalse(VerificationPolicy.NONE.hasPkiVerification());
        assertFalse(VerificationPolicy.NONE.hasAnyVerification());
        assertFalse(VerificationPolicy.NONE.hasBadgeVerification());
        assertFalse(VerificationPolicy.NONE.hasDaneVerification());
        assertFalse(VerificationPolicy.NONE.requiresIdcaTrust());
    }

    @Test
    void basicHasPkiOnly() {
        assertTrue(VerificationPolicy.BASIC.hasPkiVerification());
        assertFalse(VerificationPolicy.BASIC.hasAnyVerification());
        assertFalse(VerificationPolicy.BASIC.hasBadgeVerification());
        assertFalse(VerificationPolicy.BASIC.hasDaneVerification());
        assertTrue(VerificationPolicy.BASIC.requiresIdcaTrust());
    }

    @Test
    void enhancedHasBadgeOnly() {
        assertTrue(VerificationPolicy.ENHANCED.hasPkiVerification());
        assertTrue(VerificationPolicy.ENHANCED.hasAnyVerification());
        assertTrue(VerificationPolicy.ENHANCED.hasBadgeVerification());
        assertFalse(VerificationPolicy.ENHANCED.hasDaneVerification());
        assertTrue(VerificationPolicy.ENHANCED.requiresIdcaTrust());
    }

    @Test
    void advancedHasBothVerifications() {
        assertTrue(VerificationPolicy.ADVANCED.hasAnyVerification());
        assertTrue(VerificationPolicy.ADVANCED.hasBadgeVerification());
        assertTrue(VerificationPolicy.ADVANCED.hasDaneVerification());
        assertTrue(VerificationPolicy.ADVANCED.requiresIdcaTrust());
    }

    @Test
    void displayNamesMatchConsole() {
        assertEquals("L0 无认证", VerificationPolicy.NONE.displayName());
        assertEquals("L1 基础认证", VerificationPolicy.BASIC.displayName());
        assertEquals("L2 增强认证", VerificationPolicy.ENHANCED.displayName());
        assertEquals("L3 高级认证", VerificationPolicy.ADVANCED.displayName());
    }

    @Test
    void fromStringIsCaseInsensitive() {
        assertEquals(VerificationPolicy.NONE, VerificationPolicy.fromString("none"));
        assertEquals(VerificationPolicy.BASIC, VerificationPolicy.fromString("BASIC"));
        assertEquals(VerificationPolicy.ENHANCED, VerificationPolicy.fromString("enhanced"));
        assertEquals(VerificationPolicy.ADVANCED, VerificationPolicy.fromString("Advanced"));
    }

    @Test
    void fromStringRejectsLegacyNames() {
        assertThrows(IllegalArgumentException.class, () -> VerificationPolicy.fromString("PKI_ONLY"));
        assertThrows(IllegalArgumentException.class, () -> VerificationPolicy.fromString("BADGE_REQUIRED"));
        assertThrows(IllegalArgumentException.class, () -> VerificationPolicy.fromString("L2"));
    }

    @Test
    void noneIsServerOnly() {
        assertTrue(VerificationPolicy.NONE.isServerOnly());
        assertFalse(VerificationPolicy.BASIC.isServerOnly());
    }

    @Test
    void validateForClientRejectsNone() {
        assertThrows(IllegalArgumentException.class, VerificationPolicy.NONE::validateForClient);
        VerificationPolicy.BASIC.validateForClient();
        VerificationPolicy.ENHANCED.validateForClient();
        VerificationPolicy.ADVANCED.validateForClient();
    }

    @Test
    void allValuesAreNotNull() {
        for (VerificationPolicy policy : VerificationPolicy.values()) {
            assertNotNull(policy);
            assertNotNull(policy.name());
            assertNotNull(policy.displayName());
        }
    }
}
