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
    @DisplayName("Should reject missing av")
    void shouldRejectMissingAv() {
        assertThatThrownBy(() -> AtiDiscoveryRecord.parse("v=ati1; p=mcp; u=https://x"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("av");
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
