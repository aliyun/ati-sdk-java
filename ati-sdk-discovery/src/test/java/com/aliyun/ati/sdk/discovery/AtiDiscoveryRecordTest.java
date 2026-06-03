package com.aliyun.ati.sdk.discovery;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AtiDiscoveryRecordTest {

    @Test
    void shouldParseFullRecord() {
        String txt = "v=ati1; version=v1.0.0; url=https://agent.example.com/.well-known/ati/trust-card.json";
        AtiDiscoveryRecord record = AtiDiscoveryRecord.parse(txt);

        assertThat(record.getFormatVersion()).isEqualTo("ati1");
        assertThat(record.getVersion()).isEqualTo("v1.0.0");
        assertThat(record.getUrl()).isEqualTo("https://agent.example.com/.well-known/ati/trust-card.json");
        assertThat(record.getMode()).isEqualTo("card");
    }

    @Test
    void shouldParseDirectMode() {
        String txt = "v=ati1; version=v2.0.0; mode=direct";
        AtiDiscoveryRecord record = AtiDiscoveryRecord.parse(txt);

        assertThat(record.getMode()).isEqualTo("direct");
        assertThat(record.getUrl()).isNull();
    }

    @Test
    void shouldRejectInvalidFormatVersion() {
        assertThatThrownBy(() -> AtiDiscoveryRecord.parse("v=ans1; version=v1.0.0"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("ati1");
    }

    @Test
    void shouldRejectMissingVersion() {
        assertThatThrownBy(() -> AtiDiscoveryRecord.parse("v=ati1"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("version");
    }
}
