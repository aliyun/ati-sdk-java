package com.aliyun.ati.sdk.discovery;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AtiBadgeRecordTest {

    @Test
    void shouldParseValidBadgeRecord() {
        String txt = "v=ati-badge1; version=v1.0.0; url=https://tl.ansagent.cn:8180/tl/agents/abc-123-def";
        AtiBadgeRecord record = AtiBadgeRecord.parse(txt);

        assertThat(record.getFormatVersion()).isEqualTo("ati-badge1");
        assertThat(record.getVersion()).isEqualTo("v1.0.0");
        assertThat(record.getUrl()).isEqualTo("https://tl.ansagent.cn:8180/tl/agents/abc-123-def");
        assertThat(record.getAgentId()).isEqualTo("abc-123-def");
    }

    @Test
    void shouldExtractUuidAgentId() {
        String txt = "v=ati-badge1; version=v1.0.0; url=https://tl.ansagent.cn:8180/tl/agents/28b8f491-f110-4705-b8b9-dc8e91d452e0";
        AtiBadgeRecord record = AtiBadgeRecord.parse(txt);

        assertThat(record.getAgentId()).isEqualTo("28b8f491-f110-4705-b8b9-dc8e91d452e0");
    }

    @Test
    void shouldRejectInvalidFormatVersion() {
        assertThatThrownBy(() -> AtiBadgeRecord.parse("v=ans-badge1; version=v1.0.0; url=https://tl/agents/x"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("ati-badge1");
    }

    @Test
    void shouldRejectMissingUrl() {
        assertThatThrownBy(() -> AtiBadgeRecord.parse("v=ati-badge1; version=v1.0.0"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("url");
    }
}
