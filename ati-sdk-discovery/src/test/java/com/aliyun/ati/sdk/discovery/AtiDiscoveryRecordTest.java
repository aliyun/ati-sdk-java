package com.aliyun.ati.sdk.discovery;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AtiDiscoveryRecordTest {

    private static final String VALID_TXT =
        "v=ati1; av=v1.0.0; p=mcp; u=https://bailian.aliyun.com/agents/abc123/mcp; m=direct";

    @Test
    @DisplayName("Should parse valid discovery TXT record")
    void shouldParseValidRecord() {
        AtiDiscoveryRecord record = AtiDiscoveryRecord.parse(VALID_TXT);

        assertThat(record.getFormatVersion()).isEqualTo("ati1");
        assertThat(record.getAgentVersion()).isEqualTo("v1.0.0");
        assertThat(record.getProtocol()).isEqualTo("mcp");
        assertThat(record.getAgentUrl()).isEqualTo("https://bailian.aliyun.com/agents/abc123/mcp");
        assertThat(record.getMode()).isEqualTo("direct");
    }

    @Test
    @DisplayName("Should parse Discovery TXT when keys are reordered")
    void shouldParseReorderedKeys() {
        String txt = "u=https://bailian.aliyun.com/agents/abc123/mcp; p=mcp; av=v1.0.0; v=ati1";

        AtiDiscoveryRecord record = AtiDiscoveryRecord.parse(txt);

        assertThat(record.getFormatVersion()).isEqualTo("ati1");
        assertThat(record.getAgentVersion()).isEqualTo("v1.0.0");
        assertThat(record.getProtocol()).isEqualTo("mcp");
        assertThat(record.getAgentUrl()).isEqualTo("https://bailian.aliyun.com/agents/abc123/mcp");
    }

    @Test
    @DisplayName("Should ignore unknown keys and last-win duplicate keys")
    void shouldIgnoreUnknownKeysAndLastWinDuplicates() {
        String txt = "v=ati1; av=v1.0.0; p=mcp; u=https://first.example/mcp; extra=keep-me; "
            + "u=https://last.example/mcp";

        AtiDiscoveryRecord record = AtiDiscoveryRecord.parse(txt);

        assertThat(record.getAgentUrl()).isEqualTo("https://last.example/mcp");
        assertThat(record.getProtocol()).isEqualTo("mcp");
    }

    @Test
    @DisplayName("Should not treat uppercase V/P/U as required fields")
    void shouldRejectUppercaseRequiredKeys() {
        assertThatThrownBy(() -> AtiDiscoveryRecord.parse(
            "V=ati1; AV=v1.0.0; P=mcp; U=https://example.com/mcp"))
            .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("Should default mode to direct when omitted")
    void shouldDefaultModeToDirect() {
        String txt = "v=ati1; av=1.0.0; p=a2a; u=https://example.com/a2a";

        AtiDiscoveryRecord record = AtiDiscoveryRecord.parse(txt);

        assertThat(record.getMode()).isEqualTo("direct");
    }

    @Test
    @DisplayName("Should reject unsupported format version")
    void shouldRejectUnsupportedFormatVersion() {
        assertThatThrownBy(() -> AtiDiscoveryRecord.parse("v=ati2; av=1.0.0; p=mcp; u=https://x"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("ati1");
    }

    @Test
    @DisplayName("Should reject non-ati1 Discovery format values")
    void shouldRejectNonAti1FormatValues() {
        assertThatThrownBy(() -> AtiDiscoveryRecord.parse("v=ati-badge1; av=1.0.0; p=mcp; u=https://x"))
            .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> AtiDiscoveryRecord.parse("v=ATI1; av=1.0.0; p=mcp; u=https://x"))
            .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> AtiDiscoveryRecord.parse("v=ati; av=1.0.0; p=mcp; u=https://x"))
            .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> AtiDiscoveryRecord.parse("v=ati1b; av=1.0.0; p=mcp; u=https://x"))
            .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("Should reject missing av")
    void shouldRejectMissingAv() {
        assertThatThrownBy(() -> AtiDiscoveryRecord.parse("v=ati1; p=mcp; u=https://x"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("av");
    }

    @Test
    @DisplayName("Should accept v/V-prefixed and bare SemVer av")
    void shouldAcceptPrefixedAndBareSemVerAv() {
        assertThat(AtiDiscoveryRecord.parse("v=ati1; av=v1.0.0; p=mcp; u=https://x").getAgentVersion())
            .isEqualTo("v1.0.0");
        assertThat(AtiDiscoveryRecord.parse("v=ati1; av=V1.0.0; p=mcp; u=https://x").getAgentVersion())
            .isEqualTo("V1.0.0");
        assertThat(AtiDiscoveryRecord.parse("v=ati1; av=1.0.0; p=mcp; u=https://x").getAgentVersion())
            .isEqualTo("1.0.0");
    }

    @Test
    @DisplayName("Should reject blank or non-SemVer av")
    void shouldRejectBlankOrNonSemVerAv() {
        assertThatThrownBy(() -> AtiDiscoveryRecord.parse("v=ati1; av=; p=mcp; u=https://x"))
            .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> AtiDiscoveryRecord.parse("v=ati1; av=foo; p=mcp; u=https://x"))
            .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("Should accept only lowercase mcp, a2a, and http-api Protocol values")
    void shouldAcceptClosedLowercaseProtocols() {
        assertThat(AtiDiscoveryRecord.parse("v=ati1; av=1.0.0; p=mcp; u=https://x").getProtocol())
            .isEqualTo("mcp");
        assertThat(AtiDiscoveryRecord.parse("v=ati1; av=1.0.0; p=a2a; u=https://x").getProtocol())
            .isEqualTo("a2a");
        assertThat(AtiDiscoveryRecord.parse("v=ati1; av=1.0.0; p=http-api; u=https://x").getProtocol())
            .isEqualTo("http-api");
    }

    @Test
    @DisplayName("Should reject uppercase or unknown Protocol values")
    void shouldRejectUppercaseOrUnknownProtocol() {
        assertThatThrownBy(() -> AtiDiscoveryRecord.parse("v=ati1; av=1.0.0; p=MCP; u=https://x"))
            .isInstanceOf(IllegalArgumentException.class);
        assertThatThrownBy(() -> AtiDiscoveryRecord.parse("v=ati1; av=1.0.0; p=websocket; u=https://x"))
            .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    @DisplayName("Should parse non-blank agentUrl without HTTPS or Dual Hostname checks")
    void shouldParseNonBlankHttpUrl() {
        String txt = "v=ati1; av=1.0.0; p=mcp; u=http://example.com/mcp";

        AtiDiscoveryRecord record = AtiDiscoveryRecord.parse(txt);

        assertThat(record.getAgentUrl()).isEqualTo("http://example.com/mcp");
    }

    @Test
    @DisplayName("Should reject blank u")
    void shouldRejectBlankAgentUrl() {
        assertThatThrownBy(() -> AtiDiscoveryRecord.parse("v=ati1; av=1.0.0; p=mcp; u="))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("u");
    }

    @Test
    @DisplayName("Should reject unsupported discovery mode")
    void shouldRejectUnsupportedMode() {
        assertThatThrownBy(() ->
            AtiDiscoveryRecord.parse("v=ati1; av=1.0.0; p=mcp; u=https://x; m=card"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("mode");
    }
}
