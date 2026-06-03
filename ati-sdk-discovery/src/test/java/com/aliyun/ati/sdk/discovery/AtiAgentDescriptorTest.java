package com.aliyun.ati.sdk.discovery;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AtiAgentDescriptorTest {

    @Test
    void shouldCreateWithRequiredFields() {
        AtiAgentDescriptor descriptor = new AtiAgentDescriptor(
            "agent.example.com", "1", null, null);

        assertThat(descriptor.getAgentHost()).isEqualTo("agent.example.com");
        assertThat(descriptor.getVersion()).isEqualTo("1");
        assertThat(descriptor.getBadgeUrl()).isNull();
        assertThat(descriptor.getAgentId()).isNull();
    }

    @Test
    void shouldRejectNullAgentHost() {
        assertThatThrownBy(() -> new AtiAgentDescriptor(null, "1", null, null))
            .isInstanceOf(NullPointerException.class);
    }

    @Test
    void shouldRejectNullVersion() {
        assertThatThrownBy(() -> new AtiAgentDescriptor("agent.example.com", null, null, null))
            .isInstanceOf(NullPointerException.class);
    }
}
