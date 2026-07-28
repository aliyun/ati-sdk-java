package com.aliyun.ati.sdk.agent.verification;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Configuration and caching tests extracted from {@link DaneVerifierTest}.
 */
class DaneVerifierConfigAndCacheTest {

    private static final String TEST_HOSTNAME = "agent.example.com";
    private static final int TEST_PORT = 443;

    // ==================== DanePolicy Tests ====================

    @Test
    @DisplayName("DanePolicy.DISABLED should not verify")
    void danePolicyDisabledShouldNotVerify() {
        assertThat(DanePolicy.DISABLED.shouldVerify()).isFalse();
        assertThat(DanePolicy.DISABLED.isRequired()).isFalse();
    }

    @Test
    @DisplayName("DanePolicy.VALIDATE_IF_PRESENT should verify but not require")
    void danePolicyValidateIfPresentShouldVerifyButNotRequire() {
        assertThat(DanePolicy.VALIDATE_IF_PRESENT.shouldVerify()).isTrue();
        assertThat(DanePolicy.VALIDATE_IF_PRESENT.isRequired()).isFalse();
    }

    @Test
    @DisplayName("DanePolicy.REQUIRED should verify and require")
    void danePolicyRequiredShouldVerifyAndRequire() {
        assertThat(DanePolicy.REQUIRED.shouldVerify()).isTrue();
        assertThat(DanePolicy.REQUIRED.isRequired()).isTrue();
    }

    // ==================== DnsResolverConfig Tests ====================

    @Test
    @DisplayName("DnsResolverConfig.CLOUDFLARE should have 1.1.1.1")
    void dnsResolverConfigCloudflareShouldHaveCorrectAddress() {
        assertThat(DnsResolverConfig.CLOUDFLARE.getPrimaryAddress()).isEqualTo("1.1.1.1");
        assertThat(DnsResolverConfig.CLOUDFLARE.getSecondaryAddress()).isEqualTo("1.0.0.1");
        assertThat(DnsResolverConfig.CLOUDFLARE.isSystemResolver()).isFalse();
    }

    @Test
    @DisplayName("DnsResolverConfig.GOOGLE should have 8.8.8.8")
    void dnsResolverConfigGoogleShouldHaveCorrectAddress() {
        assertThat(DnsResolverConfig.GOOGLE.getPrimaryAddress()).isEqualTo("8.8.8.8");
        assertThat(DnsResolverConfig.GOOGLE.getSecondaryAddress()).isEqualTo("8.8.4.4");
        assertThat(DnsResolverConfig.GOOGLE.isSystemResolver()).isFalse();
    }

    @Test
    @DisplayName("DnsResolverConfig.QUAD9 should have 9.9.9.9")
    void dnsResolverConfigQuad9ShouldHaveCorrectAddress() {
        assertThat(DnsResolverConfig.QUAD9.getPrimaryAddress()).isEqualTo("9.9.9.9");
        assertThat(DnsResolverConfig.QUAD9.isSystemResolver()).isFalse();
    }

    @Test
    @DisplayName("DnsResolverConfig.SYSTEM should have null addresses")
    void dnsResolverConfigSystemShouldHaveNullAddresses() {
        assertThat(DnsResolverConfig.SYSTEM.getPrimaryAddress()).isNull();
        assertThat(DnsResolverConfig.SYSTEM.getSecondaryAddress()).isNull();
        assertThat(DnsResolverConfig.SYSTEM.isSystemResolver()).isTrue();
    }

    // ==================== DaneConfig Tests ====================

    @Test
    @DisplayName("DaneConfig.defaults() should have expected values")
    void daneConfigDefaultsShouldHaveExpectedValues() {
        DaneConfig config = DaneConfig.defaults();

        assertThat(config.policy()).isEqualTo(DanePolicy.VALIDATE_IF_PRESENT);
        assertThat(config.resolver()).isEqualTo(DnsResolverConfig.CLOUDFLARE);
        assertThat(config.validationMode()).isEqualTo(DnssecValidationMode.VALIDATE_IN_CODE);
        assertThat(config.cacheTtl()).isEqualTo(DaneConfig.DEFAULT_CACHE_TTL);
    }

    @Test
    @DisplayName("DaneConfig.disabled() should have disabled policy")
    void daneConfigDisabledShouldHaveDisabledPolicy() {
        DaneConfig config = DaneConfig.disabled();

        assertThat(config.policy()).isEqualTo(DanePolicy.DISABLED);
        assertThat(config.validationMode()).isEqualTo(DnssecValidationMode.TRUST_RESOLVER);
    }

    @Test
    @DisplayName("DaneConfig builder should work correctly")
    void daneConfigBuilderShouldWorkCorrectly() {
        DaneConfig config = DaneConfig.builder()
            .policy(DanePolicy.REQUIRED)
            .resolver(DnsResolverConfig.GOOGLE)
            .cacheTtl(java.time.Duration.ofMinutes(30))
            .build();

        assertThat(config.policy()).isEqualTo(DanePolicy.REQUIRED);
        assertThat(config.resolver()).isEqualTo(DnsResolverConfig.GOOGLE);
        assertThat(config.validationMode()).isEqualTo(DnssecValidationMode.VALIDATE_IN_CODE);
        assertThat(config.cacheTtl()).isEqualTo(java.time.Duration.ofMinutes(30));
    }

    @Test
    @DisplayName("DaneConfig builder with VALIDATE_IN_CODE mode")
    void daneConfigBuilderWithValidateInCodeMode() {
        DaneConfig config = DaneConfig.builder()
            .policy(DanePolicy.REQUIRED)
            .resolver(DnsResolverConfig.SYSTEM)
            .validationMode(DnssecValidationMode.VALIDATE_IN_CODE)
            .cacheTtl(java.time.Duration.ofMinutes(15))
            .build();

        assertThat(config.policy()).isEqualTo(DanePolicy.REQUIRED);
        assertThat(config.resolver()).isEqualTo(DnsResolverConfig.SYSTEM);
        assertThat(config.validationMode()).isEqualTo(DnssecValidationMode.VALIDATE_IN_CODE);
        assertThat(config.cacheTtl()).isEqualTo(java.time.Duration.ofMinutes(15));
    }

    // ==================== DnssecValidationMode Tests ====================

    @Test
    @DisplayName("DnssecValidationMode.TRUST_RESOLVER should require DNSSEC resolver")
    void dnssecValidationModeTrustResolverShouldRequireDnssecResolver() {
        assertThat(DnssecValidationMode.TRUST_RESOLVER.isInCodeValidation()).isFalse();
        assertThat(DnssecValidationMode.TRUST_RESOLVER.requiresDnssecResolver()).isTrue();
    }

    @Test
    @DisplayName("DnssecValidationMode.VALIDATE_IN_CODE should not require DNSSEC resolver")
    void dnssecValidationModeValidateInCodeShouldNotRequireDnssecResolver() {
        assertThat(DnssecValidationMode.VALIDATE_IN_CODE.isInCodeValidation()).isTrue();
        assertThat(DnssecValidationMode.VALIDATE_IN_CODE.requiresDnssecResolver()).isFalse();
    }

    // ==================== DefaultDaneTlsaVerifier Config Tests ====================

    @Test
    @DisplayName("DefaultDaneTlsaVerifier with DISABLED policy should skip verification")
    void defaultDaneTlsaVerifierWithDisabledPolicyShouldSkipVerification() {
        DaneConfig config = DaneConfig.builder()
            .policy(DanePolicy.DISABLED)
            .build();

        DefaultDaneTlsaVerifier verifier = new DefaultDaneTlsaVerifier(config);

        assertThat(verifier.getPolicy()).isEqualTo(DanePolicy.DISABLED);

        // Verify that verifyTlsa returns skipped result
        DaneTlsaVerifier.TlsaResult result = verifier.verifyTlsa(TEST_HOSTNAME, TEST_PORT);
        assertThat(result.isSkipped()).isTrue();
        assertThat(result.reason()).contains("disabled");
    }

    @Test
    @DisplayName("DefaultDaneTlsaVerifier with DISABLED policy should return false for hasTlsaRecord")
    void defaultDaneTlsaVerifierWithDisabledPolicyShouldReturnFalseForHasTlsaRecord() {
        DaneConfig config = DaneConfig.builder()
            .policy(DanePolicy.DISABLED)
            .build();

        DefaultDaneTlsaVerifier verifier = new DefaultDaneTlsaVerifier(config);

        // Should return false without making DNS query
        assertThat(verifier.hasTlsaRecord(TEST_HOSTNAME, TEST_PORT)).isFalse();
    }

    @Test
    @DisplayName("DefaultDaneTlsaVerifier with DISABLED policy should return empty expectations")
    void defaultDaneTlsaVerifierWithDisabledPolicyShouldReturnEmptyExpectations() throws Exception {
        DaneConfig config = DaneConfig.builder()
            .policy(DanePolicy.DISABLED)
            .build();

        DefaultDaneTlsaVerifier verifier = new DefaultDaneTlsaVerifier(config);

        // Should return empty list without making DNS query
        java.util.List<DaneTlsaVerifier.TlsaExpectation> expectations =
            verifier.getTlsaExpectations(TEST_HOSTNAME, TEST_PORT);
        assertThat(expectations).isEmpty();
    }

    @Test
    @DisplayName("TlsaResult.skipped should work correctly")
    void tlsaResultSkippedShouldWorkCorrectly() {
        DaneTlsaVerifier.TlsaResult result = DaneTlsaVerifier.TlsaResult.skipped("Test reason");

        assertThat(result.verified()).isFalse();
        assertThat(result.isSkipped()).isTrue();
        assertThat(result.reason()).isEqualTo("Test reason");
        assertThat(result.matchType()).isEqualTo("SKIPPED");
    }

    // ==================== DefaultDaneTlsaVerifier ValidationMode Tests ====================

    @Test
    @DisplayName("DefaultDaneTlsaVerifier with TRUST_RESOLVER mode")
    void defaultDaneTlsaVerifierWithTrustResolverMode() {
        DaneConfig config = DaneConfig.builder()
            .validationMode(DnssecValidationMode.TRUST_RESOLVER)
            .build();

        DefaultDaneTlsaVerifier verifier = new DefaultDaneTlsaVerifier(config);

        assertThat(verifier.getValidationMode()).isEqualTo(DnssecValidationMode.TRUST_RESOLVER);
    }

    @Test
    @DisplayName("DefaultDaneTlsaVerifier with VALIDATE_IN_CODE mode")
    void defaultDaneTlsaVerifierWithValidateInCodeMode() {
        DaneConfig config = DaneConfig.builder()
            .validationMode(DnssecValidationMode.VALIDATE_IN_CODE)
            .resolver(DnsResolverConfig.SYSTEM)  // Can use system resolver with in-code validation
            .build();

        DefaultDaneTlsaVerifier verifier = new DefaultDaneTlsaVerifier(config);

        assertThat(verifier.getValidationMode()).isEqualTo(DnssecValidationMode.VALIDATE_IN_CODE);
    }

    @Test
    @DisplayName("DefaultDaneTlsaVerifier with VALIDATE_IN_CODE and DISABLED policy should skip")
    void defaultDaneTlsaVerifierWithValidateInCodeAndDisabledPolicyShouldSkip() {
        DaneConfig config = DaneConfig.builder()
            .policy(DanePolicy.DISABLED)
            .validationMode(DnssecValidationMode.VALIDATE_IN_CODE)
            .build();

        DefaultDaneTlsaVerifier verifier = new DefaultDaneTlsaVerifier(config);

        // Verify that policy takes precedence - still skips even with VALIDATE_IN_CODE
        DaneTlsaVerifier.TlsaResult result = verifier.verifyTlsa(TEST_HOSTNAME, TEST_PORT);
        assertThat(result.isSkipped()).isTrue();
        assertThat(result.reason()).contains("disabled");
    }

    @Test
    @DisplayName("DefaultDaneTlsaVerifier defaults to VALIDATE_IN_CODE mode")
    void defaultDaneTlsaVerifierDefaultsToValidateInCodeMode() {
        DaneConfig config = DaneConfig.defaults();
        DefaultDaneTlsaVerifier verifier = new DefaultDaneTlsaVerifier(config);

        assertThat(verifier.getValidationMode()).isEqualTo(DnssecValidationMode.VALIDATE_IN_CODE);
    }

    // ==================== TLSA Lookup Caching Tests ====================

    @Test
    @DisplayName("Cache should start empty")
    void cacheShouldStartEmpty() {
        DaneConfig config = DaneConfig.builder()
            .policy(DanePolicy.DISABLED) // Disabled to avoid DNS
            .cacheTtl(java.time.Duration.ofMinutes(5))
            .build();

        DefaultDaneTlsaVerifier verifier = new DefaultDaneTlsaVerifier(config);

        assertThat(verifier.cacheSize()).isZero();
    }

    @Test
    @DisplayName("clearCache should remove all entries")
    void clearCacheShouldRemoveAllEntries() {
        DaneConfig config = DaneConfig.builder()
            .policy(DanePolicy.DISABLED)
            .cacheTtl(java.time.Duration.ofMinutes(5))
            .build();

        DefaultDaneTlsaVerifier verifier = new DefaultDaneTlsaVerifier(config);

        // Cache starts empty
        assertThat(verifier.cacheSize()).isZero();

        // Clear should work even when empty
        verifier.clearCache();
        assertThat(verifier.cacheSize()).isZero();
    }

    @Test
    @DisplayName("invalidate should work without error on non-existent entry")
    void invalidateShouldWorkOnNonExistentEntry() {
        DaneConfig config = DaneConfig.builder()
            .policy(DanePolicy.DISABLED)
            .cacheTtl(java.time.Duration.ofMinutes(5))
            .build();

        DefaultDaneTlsaVerifier verifier = new DefaultDaneTlsaVerifier(config);

        // Should not throw even if entry doesn't exist
        verifier.invalidate("nonexistent.example.com", 443);
        assertThat(verifier.cacheSize()).isZero();
    }

    @Test
    @DisplayName("Cache should be disabled when cacheTtl is zero")
    void cacheShouldBeDisabledWhenTtlIsZero() throws Exception {
        // Use a testable verifier that tracks DNS calls
        TestableDefaultDaneTlsaVerifier verifier = new TestableDefaultDaneTlsaVerifier(
            DaneConfig.builder()
                .policy(DanePolicy.VALIDATE_IF_PRESENT)
                .cacheTtl(java.time.Duration.ZERO) // Caching disabled
                .build()
        );

        // First call
        verifier.getTlsaExpectations("test.example.com", 443);
        assertThat(verifier.getDnsLookupCount()).isEqualTo(1);

        // Second call - should still do DNS lookup since caching is disabled
        verifier.getTlsaExpectations("test.example.com", 443);
        assertThat(verifier.getDnsLookupCount()).isEqualTo(2);

        // Cache should remain empty
        assertThat(verifier.cacheSize()).isZero();
    }

    @Test
    @DisplayName("Cache should store results when cacheTtl is positive")
    void cacheShouldStoreResultsWhenTtlIsPositive() throws Exception {
        TestableDefaultDaneTlsaVerifier verifier = new TestableDefaultDaneTlsaVerifier(
            DaneConfig.builder()
                .policy(DanePolicy.VALIDATE_IF_PRESENT)
                .cacheTtl(java.time.Duration.ofMinutes(5))
                .build()
        );

        // First call - should do DNS lookup
        verifier.getTlsaExpectations("test.example.com", 443);
        assertThat(verifier.getDnsLookupCount()).isEqualTo(1);
        assertThat(verifier.cacheSize()).isEqualTo(1);

        // Second call - should use cache, not DNS
        verifier.getTlsaExpectations("test.example.com", 443);
        assertThat(verifier.getDnsLookupCount()).isEqualTo(1); // Still 1, used cache
        assertThat(verifier.cacheSize()).isEqualTo(1);
    }

    @Test
    @DisplayName("Cache should store different entries for different hosts")
    void cacheShouldStoreDifferentEntriesForDifferentHosts() throws Exception {
        TestableDefaultDaneTlsaVerifier verifier = new TestableDefaultDaneTlsaVerifier(
            DaneConfig.builder()
                .policy(DanePolicy.VALIDATE_IF_PRESENT)
                .cacheTtl(java.time.Duration.ofMinutes(5))
                .build()
        );

        // Look up first host
        verifier.getTlsaExpectations("host1.example.com", 443);
        assertThat(verifier.cacheSize()).isEqualTo(1);

        // Look up second host
        verifier.getTlsaExpectations("host2.example.com", 443);
        assertThat(verifier.cacheSize()).isEqualTo(2);

        // Look up first host again - should use cache
        verifier.getTlsaExpectations("host1.example.com", 443);
        assertThat(verifier.getDnsLookupCount()).isEqualTo(2); // Only 2 DNS lookups total
    }

    @Test
    @DisplayName("Cache should store different entries for different ports")
    void cacheShouldStoreDifferentEntriesForDifferentPorts() throws Exception {
        TestableDefaultDaneTlsaVerifier verifier = new TestableDefaultDaneTlsaVerifier(
            DaneConfig.builder()
                .policy(DanePolicy.VALIDATE_IF_PRESENT)
                .cacheTtl(java.time.Duration.ofMinutes(5))
                .build()
        );

        // Look up port 443
        verifier.getTlsaExpectations("test.example.com", 443);
        assertThat(verifier.cacheSize()).isEqualTo(1);

        // Look up port 8443 - different cache entry
        verifier.getTlsaExpectations("test.example.com", 8443);
        assertThat(verifier.cacheSize()).isEqualTo(2);
    }

    @Test
    @DisplayName("invalidate should remove specific cache entry")
    void invalidateShouldRemoveSpecificCacheEntry() throws Exception {
        TestableDefaultDaneTlsaVerifier verifier = new TestableDefaultDaneTlsaVerifier(
            DaneConfig.builder()
                .policy(DanePolicy.VALIDATE_IF_PRESENT)
                .cacheTtl(java.time.Duration.ofMinutes(5))
                .build()
        );

        // Populate cache with two entries
        verifier.getTlsaExpectations("host1.example.com", 443);
        verifier.getTlsaExpectations("host2.example.com", 443);
        assertThat(verifier.cacheSize()).isEqualTo(2);

        // Invalidate one entry
        verifier.invalidate("host1.example.com", 443);
        assertThat(verifier.cacheSize()).isEqualTo(1);

        // Next lookup for host1 should do DNS again
        verifier.getTlsaExpectations("host1.example.com", 443);
        assertThat(verifier.getDnsLookupCount()).isEqualTo(3); // 2 initial + 1 after invalidate
    }

    @Test
    @DisplayName("clearCache should remove all cache entries")
    void clearCacheShouldRemoveAllCacheEntries() throws Exception {
        TestableDefaultDaneTlsaVerifier verifier = new TestableDefaultDaneTlsaVerifier(
            DaneConfig.builder()
                .policy(DanePolicy.VALIDATE_IF_PRESENT)
                .cacheTtl(java.time.Duration.ofMinutes(5))
                .build()
        );

        // Populate cache
        verifier.getTlsaExpectations("host1.example.com", 443);
        verifier.getTlsaExpectations("host2.example.com", 443);
        verifier.getTlsaExpectations("host3.example.com", 443);
        assertThat(verifier.cacheSize()).isEqualTo(3);

        // Clear all
        verifier.clearCache();
        assertThat(verifier.cacheSize()).isZero();

        // Next lookups should all do DNS
        verifier.getTlsaExpectations("host1.example.com", 443);
        assertThat(verifier.getDnsLookupCount()).isEqualTo(4); // 3 initial + 1 after clear
    }

    @Test
    @DisplayName("Empty TLSA results should also be cached")
    void emptyTlsaResultsShouldAlsoBeCached() throws Exception {
        TestableDefaultDaneTlsaVerifier verifier = new TestableDefaultDaneTlsaVerifier(
            DaneConfig.builder()
                .policy(DanePolicy.VALIDATE_IF_PRESENT)
                .cacheTtl(java.time.Duration.ofMinutes(5))
                .build()
        );

        // Look up host with no TLSA records
        List<DaneTlsaVerifier.TlsaExpectation> result1 = verifier.getTlsaExpectations("no-tlsa.example.com", 443);
        assertThat(result1).isEmpty();
        assertThat(verifier.getDnsLookupCount()).isEqualTo(1);
        assertThat(verifier.cacheSize()).isEqualTo(1); // Empty result is cached

        // Second lookup should use cache
        List<DaneTlsaVerifier.TlsaExpectation> result2 = verifier.getTlsaExpectations("no-tlsa.example.com", 443);
        assertThat(result2).isEmpty();
        assertThat(verifier.getDnsLookupCount()).isEqualTo(1); // No additional DNS lookup
    }

    // ==================== Testable Subclass for Caching Tests ====================

    /**
     * Testable subclass that overrides DNS lookup to avoid real network calls.
     * Tracks the number of DNS lookups to verify caching behavior.
     */
    private static class TestableDefaultDaneTlsaVerifier extends DefaultDaneTlsaVerifier {
        private int dnsLookupCount = 0;

        TestableDefaultDaneTlsaVerifier(DaneConfig config) {
            super(config);
        }

        int getDnsLookupCount() {
            return dnsLookupCount;
        }

        @Override
        protected List<TlsaRecordData> performDnsLookup(String tlsaName) {
            dnsLookupCount++;
            // Return empty list to simulate no TLSA records found
            // This avoids real DNS lookups while still exercising the caching logic
            return List.of();
        }
    }
}
