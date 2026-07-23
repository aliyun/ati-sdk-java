package com.aliyun.ati.sdk.discovery;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class AgentDetailTest {

    @Test
    @DisplayName("Should have null fields by default")
    void shouldHaveNullFieldsByDefault() {
        AgentDetail detail = new AgentDetail();

        assertThat(detail.getAgentHost()).isNull();
        assertThat(detail.getAccessHost()).isNull();
        assertThat(detail.getAgentVersion()).isNull();
        assertThat(detail.getEndpoints()).isNull();
    }

    @Test
    @DisplayName("Should set and get core fields")
    void shouldSetAndGetCoreFields() {
        AgentDetail detail = new AgentDetail();
        detail.setAgentHost("abc123.bailian.aliyun.com");
        detail.setAccessHost("bailian.aliyun.com");
        detail.setAgentVersion("1.0.0");

        assertThat(detail.getAgentHost()).isEqualTo("abc123.bailian.aliyun.com");
        assertThat(detail.getAccessHost()).isEqualTo("bailian.aliyun.com");
        assertThat(detail.getAgentVersion()).isEqualTo("1.0.0");
    }

    @Test
    @DisplayName("hostnamePair should expose identity and access hostnames")
    void hostnamePairShouldExposeHostnames() {
        AgentDetail detail = new AgentDetail();
        detail.setAgentHost("abc123.bailian.aliyun.com");
        detail.setAccessHost("bailian.aliyun.com");

        AgentDetail.HostnamePair pair = detail.hostnamePair();

        assertThat(pair.identityHost()).isEqualTo("abc123.bailian.aliyun.com");
        assertThat(pair.accessHost()).isEqualTo("bailian.aliyun.com");
    }

    @Test
    @DisplayName("extractAccessHost should derive host from endpoint URL")
    void extractAccessHostShouldDeriveHostFromEndpointUrl() {
        AgentEndpoint endpoint = new AgentEndpoint();
        endpoint.setAgentUrl("https://bailian.aliyun.com/agents/abc123/mcp");

        String accessHost = AgentDetail.extractAccessHost(List.of(endpoint));

        assertThat(accessHost).isEqualTo("bailian.aliyun.com");
    }

    @Test
    @DisplayName("toString should include key fields")
    void toStringShouldIncludeKeyFields() {
        AgentDetail detail = new AgentDetail();
        detail.setAgentHost("abc123.bailian.aliyun.com");
        detail.setAccessHost("bailian.aliyun.com");
        detail.setAgentVersion("2.0.0");
        detail.setEndpoints(List.of());

        String str = detail.toString();

        assertThat(str).contains("abc123.bailian.aliyun.com");
        assertThat(str).contains("bailian.aliyun.com");
        assertThat(str).contains("2.0.0");
    }
}
