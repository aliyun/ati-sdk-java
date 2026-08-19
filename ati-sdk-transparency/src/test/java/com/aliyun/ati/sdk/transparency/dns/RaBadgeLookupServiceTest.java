package com.aliyun.ati.sdk.transparency.dns;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Unit tests for {@link RaBadgeLookupService}.
 *
 * <p>These tests use a testable subclass that simulates DNS responses
 * without making actual network calls.</p>
 */
class RaBadgeLookupServiceTest {

    private static final String TEST_HOSTNAME = "agent.example.com";
    private static final String TEST_AGENT_ID = "6bf2b7a9-1383-4e33-a945-845f34af7526";
    private static final String TEST_AGENT_ID_V2 = "7cf3c8b0-2494-5f44-b056-956f45bf8637";

    @Test
    @DisplayName("Should return _ati-badge when record exists")
    void shouldReturnAtiBadgeWhenRecordExists() {
        Map<String, String> dnsRecords = new HashMap<>();
        dnsRecords.put("_ati-badge." + TEST_HOSTNAME,
            "v=ati-badge1; av=1.0.0; u=https://tl.atiagent.cn/v1/agents/" + TEST_AGENT_ID);

        TestableRaBadgeLookupService service = new TestableRaBadgeLookupService(dnsRecords);

        List<RaBadgeRecord> badges = service.lookupBadges(TEST_HOSTNAME);

        assertThat(badges).hasSize(1);
        assertThat(badges.get(0).agentId()).isEqualTo(TEST_AGENT_ID);
        assertThat(badges.get(0).badgeVersion()).isEqualTo("ati-badge1");
    }

    @Test
    @DisplayName("Should return empty when no _ati-badge exists")
    void shouldReturnEmptyWhenNoAtiBadgeExists() {
        Map<String, String> dnsRecords = new HashMap<>();
        TestableRaBadgeLookupService service = new TestableRaBadgeLookupService(dnsRecords);

        List<RaBadgeRecord> badges = service.lookupBadges(TEST_HOSTNAME);

        assertThat(badges).isEmpty();
    }

    @Test
    @DisplayName("lookupBadge() should return first _ati-badge record")
    void lookupBadgeShouldReturnFirstAtiBadgeRecord() {
        Map<String, String> dnsRecords = new HashMap<>();
        dnsRecords.put("_ati-badge." + TEST_HOSTNAME,
            "v=ati-badge1; av=1.0.0; u=https://tl.atiagent.cn/v1/agents/" + TEST_AGENT_ID);

        TestableRaBadgeLookupService service = new TestableRaBadgeLookupService(dnsRecords);

        RaBadgeRecord badge = service.lookupBadge(TEST_HOSTNAME);

        assertThat(badge).isNotNull();
        assertThat(badge.agentId()).isEqualTo(TEST_AGENT_ID);
    }

    @Test
    @DisplayName("hasBadgeRecord() should return true when _ati-badge exists")
    void hasBadgeRecordShouldReturnTrueWhenAtiBadgeExists() {
        Map<String, String> dnsRecords = new HashMap<>();
        dnsRecords.put("_ati-badge." + TEST_HOSTNAME,
            "v=ati-badge1; av=1.0.0; u=https://tl.atiagent.cn/v1/agents/" + TEST_AGENT_ID);

        TestableRaBadgeLookupService service = new TestableRaBadgeLookupService(dnsRecords);

        assertThat(service.hasBadgeRecord(TEST_HOSTNAME)).isTrue();
    }

    @Test
    @DisplayName("lookupBadges should return empty list for null hostname")
    void lookupBadgesShouldReturnEmptyListForNullHostname() {
        TestableRaBadgeLookupService service = new TestableRaBadgeLookupService(new HashMap<>());

        assertThat(service.lookupBadges(null)).isEmpty();
    }

    @Test
    @DisplayName("lookupBadges should return empty list for blank hostname")
    void lookupBadgesShouldReturnEmptyListForBlankHostname() {
        TestableRaBadgeLookupService service = new TestableRaBadgeLookupService(new HashMap<>());

        assertThat(service.lookupBadges("   ")).isEmpty();
    }

    @Test
    @DisplayName("lookupBadge should return null when no badges exist")
    void lookupBadgeShouldReturnNullWhenNoBadgesExist() {
        TestableRaBadgeLookupService service = new TestableRaBadgeLookupService(new HashMap<>());

        assertThat(service.lookupBadge(TEST_HOSTNAME)).isNull();
    }

    @Test
    @DisplayName("hasBadgeRecord should return false when no badges exist")
    void hasBadgeRecordShouldReturnFalseWhenNoBadgesExist() {
        TestableRaBadgeLookupService service = new TestableRaBadgeLookupService(new HashMap<>());

        assertThat(service.hasBadgeRecord(TEST_HOSTNAME)).isFalse();
    }

    @Test
    @DisplayName("lookupBadges should normalize hostname with trailing dot")
    void lookupBadgesShouldNormalizeHostnameWithTrailingDot() {
        Map<String, String> dnsRecords = new HashMap<>();
        dnsRecords.put("_ati-badge." + TEST_HOSTNAME,
            "v=ati-badge1; av=1.0.0; u=https://tl.atiagent.cn/v1/agents/" + TEST_AGENT_ID);

        TestableRaBadgeLookupService service = new TestableRaBadgeLookupService(dnsRecords);

        List<RaBadgeRecord> badges = service.lookupBadges(TEST_HOSTNAME + ".");

        assertThat(badges).hasSize(1);
        assertThat(badges.get(0).agentId()).isEqualTo(TEST_AGENT_ID);
    }

    @Test
    @DisplayName("lookupBadges should return multiple records for version rotation")
    void lookupBadgesShouldReturnMultipleRecordsForVersionRotation() {
        TestableRaBadgeLookupServiceMultiple service = new TestableRaBadgeLookupServiceMultiple();
        service.addRecord("_ati-badge." + TEST_HOSTNAME,
            "v=ati-badge1; av=1.0.0; u=https://tl.atiagent.cn/v1/agents/" + TEST_AGENT_ID);
        service.addRecord("_ati-badge." + TEST_HOSTNAME,
            "v=ati-badge1; av=2.0.0; u=https://tl.atiagent.cn/v1/agents/" + TEST_AGENT_ID_V2);

        List<RaBadgeRecord> badges = service.lookupBadges(TEST_HOSTNAME);

        assertThat(badges).hasSize(2);
    }

    @Test
    @DisplayName("lookupBadges should filter out invalid badge formats")
    void lookupBadgesShouldFilterOutInvalidBadgeFormats() {
        Map<String, String> dnsRecords = new HashMap<>();
        dnsRecords.put("_ati-badge." + TEST_HOSTNAME,
            "v=unsupported-format; av=1.0.0; u=https://tl.atiagent.cn/v1/agents/" + TEST_AGENT_ID);

        TestableRaBadgeLookupService service = new TestableRaBadgeLookupService(dnsRecords);

        assertThat(service.lookupBadges(TEST_HOSTNAME)).isEmpty();
    }

    @Test
    @DisplayName("lookupBadges should parse reordered av=/u= and skip obsolete version=/url=")
    void lookupBadgesShouldConsumeAvUParseAndSkipObsoleteKeys() {
        TestableRaBadgeLookupServiceMultiple service = new TestableRaBadgeLookupServiceMultiple();
        service.addRecord("_ati-badge." + TEST_HOSTNAME,
            "u=https://tl.atiagent.cn/v1/agents/" + TEST_AGENT_ID + "; av=1.0.0; v=ati-badge1");
        service.addRecord("_ati-badge." + TEST_HOSTNAME,
            "v=ati-badge1; version=1.0.0; url=https://tl.atiagent.cn/v1/agents/" + TEST_AGENT_ID_V2);

        List<RaBadgeRecord> badges = service.lookupBadges(TEST_HOSTNAME);

        assertThat(badges).hasSize(1);
        assertThat(badges.get(0).agentId()).isEqualTo(TEST_AGENT_ID);
        assertThat(badges.get(0).agentVersion()).isEqualTo("1.0.0");
    }

    @Test
    @DisplayName("Should handle lookup exception gracefully")
    void shouldHandleLookupExceptionGracefully() {
        TestableRaBadgeLookupServiceWithException service = new TestableRaBadgeLookupServiceWithException();

        assertThat(service.lookupBadges(TEST_HOSTNAME)).isEmpty();
    }

    @Test
    @DisplayName("Should create service with default constructor")
    void shouldCreateServiceWithDefaultConstructor() {
        assertThat(new RaBadgeLookupService()).isNotNull();
    }

    @Test
    @DisplayName("Should create service with custom DNS server")
    void shouldCreateServiceWithCustomDnsServer() {
        assertThat(new RaBadgeLookupService("8.8.8.8", Duration.ofSeconds(10))).isNotNull();
    }

    private static class TestableRaBadgeLookupService extends RaBadgeLookupService {

        private final Map<String, String> mockDnsRecords;

        TestableRaBadgeLookupService(Map<String, String> mockDnsRecords) {
            super(null, Duration.ofSeconds(1));
            this.mockDnsRecords = mockDnsRecords;
        }

        @Override
        protected List<String> lookupTxtRecords(String dnsName) {
            String record = mockDnsRecords.get(dnsName);
            return record != null ? List.of(record) : List.of();
        }
    }

    private static class TestableRaBadgeLookupServiceMultiple extends RaBadgeLookupService {

        private final Map<String, List<String>> mockDnsRecords = new HashMap<>();

        TestableRaBadgeLookupServiceMultiple() {
            super(null, Duration.ofSeconds(1));
        }

        void addRecord(String dnsName, String record) {
            mockDnsRecords.computeIfAbsent(dnsName, k -> new ArrayList<>()).add(record);
        }

        @Override
        protected List<String> lookupTxtRecords(String dnsName) {
            return mockDnsRecords.getOrDefault(dnsName, List.of());
        }
    }

    private static class TestableRaBadgeLookupServiceWithException extends RaBadgeLookupService {

        TestableRaBadgeLookupServiceWithException() {
            super(null, Duration.ofSeconds(1));
        }

        @Override
        protected List<String> lookupTxtRecords(String dnsName) {
            throw new RuntimeException("Simulated DNS lookup failure");
        }
    }
}
