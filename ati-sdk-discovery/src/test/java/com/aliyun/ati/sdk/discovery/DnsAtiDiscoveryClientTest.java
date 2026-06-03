package com.aliyun.ati.sdk.discovery;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DnsAtiDiscoveryClientTest {

    @Test
    void shouldRejectNullAtiName() {
        DnsAtiDiscoveryClient client = new DnsAtiDiscoveryClient();
        assertThatThrownBy(() -> client.discover(null))
            .isInstanceOf(NullPointerException.class);
    }

    @Test
    void shouldReturnDescriptorWithNullBadgeWhenDnsUnavailable() {
        DnsAtiDiscoveryClient client = new DnsAtiDiscoveryClient();
        AtiName name = AtiName.parse("ati://v1.nonexistent.invalid");

        AtiAgentDescriptor descriptor = client.discover(name);

        assertThat(descriptor.getAgentHost()).isEqualTo("nonexistent.invalid");
        assertThat(descriptor.getVersion()).isEqualTo("1");
        assertThat(descriptor.getBadgeUrl()).isNull();
        assertThat(descriptor.getAgentId()).isNull();
    }
}
