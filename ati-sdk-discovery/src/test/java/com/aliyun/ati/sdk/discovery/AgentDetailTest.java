package com.aliyun.ati.sdk.discovery;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link AgentDetail}.
 */
class AgentDetailTest {

    @Test
    @DisplayName("Should have null fields by default")
    void shouldHaveNullFieldsByDefault() {
        AgentDetail detail = new AgentDetail();

        assertThat(detail.getAgentId()).isNull();
        assertThat(detail.getAgentDisplayName()).isNull();
        assertThat(detail.getAgentHost()).isNull();
        assertThat(detail.getAgentVersion()).isNull();
        assertThat(detail.getAgentDescription()).isNull();
        assertThat(detail.getStatus()).isNull();
        assertThat(detail.getTrustLevel()).isNull();
        assertThat(detail.getEndpoints()).isNull();
    }

    @Test
    @DisplayName("Should set and get agentId")
    void shouldSetAndGetAgentId() {
        AgentDetail detail = new AgentDetail();
        detail.setAgentId("agent-123");

        assertThat(detail.getAgentId()).isEqualTo("agent-123");
    }

    @Test
    @DisplayName("Should set and get agentDisplayName")
    void shouldSetAndGetAgentDisplayName() {
        AgentDetail detail = new AgentDetail();
        detail.setAgentDisplayName("My Agent");

        assertThat(detail.getAgentDisplayName()).isEqualTo("My Agent");
    }

    @Test
    @DisplayName("Should set and get agentHost")
    void shouldSetAndGetAgentHost() {
        AgentDetail detail = new AgentDetail();
        detail.setAgentHost("agent.example.com");

        assertThat(detail.getAgentHost()).isEqualTo("agent.example.com");
    }

    @Test
    @DisplayName("Should set and get agentVersion")
    void shouldSetAndGetAgentVersion() {
        AgentDetail detail = new AgentDetail();
        detail.setAgentVersion("1.0.0");

        assertThat(detail.getAgentVersion()).isEqualTo("1.0.0");
    }

    @Test
    @DisplayName("Should set and get agentDescription")
    void shouldSetAndGetAgentDescription() {
        AgentDetail detail = new AgentDetail();
        detail.setAgentDescription("A test agent");

        assertThat(detail.getAgentDescription()).isEqualTo("A test agent");
    }

    @Test
    @DisplayName("Should set and get status")
    void shouldSetAndGetStatus() {
        AgentDetail detail = new AgentDetail();
        detail.setStatus("ACTIVE");

        assertThat(detail.getStatus()).isEqualTo("ACTIVE");
    }

    @Test
    @DisplayName("Should set and get trustLevel")
    void shouldSetAndGetTrustLevel() {
        AgentDetail detail = new AgentDetail();
        detail.setTrustLevel("HIGH");

        assertThat(detail.getTrustLevel()).isEqualTo("HIGH");
    }

    @Test
    @DisplayName("Should set and get endpoints")
    void shouldSetAndGetEndpoints() {
        AgentDetail detail = new AgentDetail();
        List<AgentEndpoint> endpoints = new ArrayList<>();
        AgentEndpoint ep = new AgentEndpoint();
        ep.setProtocol("A2A");
        endpoints.add(ep);

        detail.setEndpoints(endpoints);

        assertThat(detail.getEndpoints()).hasSize(1);
        assertThat(detail.getEndpoints().get(0).getProtocol()).isEqualTo("A2A");
    }

    @Test
    @DisplayName("Should support empty endpoints list")
    void shouldSupportEmptyEndpointsList() {
        AgentDetail detail = new AgentDetail();
        detail.setEndpoints(List.of());

        assertThat(detail.getEndpoints()).isEmpty();
    }

    @Test
    @DisplayName("toString should include key fields")
    void toStringShouldIncludeKeyFields() {
        AgentDetail detail = new AgentDetail();
        detail.setAgentId("agent-456");
        detail.setAgentHost("agent.example.com");
        detail.setAgentVersion("2.0.0");
        detail.setStatus("ACTIVE");

        String str = detail.toString();

        assertThat(str).contains("agent-456");
        assertThat(str).contains("agent.example.com");
        assertThat(str).contains("2.0.0");
        assertThat(str).contains("ACTIVE");
    }

    @Test
    @DisplayName("toString should handle null fields gracefully")
    void toStringShouldHandleNullFields() {
        AgentDetail detail = new AgentDetail();

        String str = detail.toString();

        assertThat(str).contains("AgentDetail");
        assertThat(str).contains("null");
    }

    @Test
    @DisplayName("Should populate all fields together")
    void shouldPopulateAllFieldsTogether() {
        AgentDetail detail = new AgentDetail();
        detail.setAgentId("id-1");
        detail.setAgentDisplayName("Display Name");
        detail.setAgentHost("host.example.com");
        detail.setAgentVersion("3.1.0");
        detail.setAgentDescription("Full description");
        detail.setStatus("PENDING");
        detail.setTrustLevel("MEDIUM");
        detail.setEndpoints(List.of());

        assertThat(detail.getAgentId()).isEqualTo("id-1");
        assertThat(detail.getAgentDisplayName()).isEqualTo("Display Name");
        assertThat(detail.getAgentHost()).isEqualTo("host.example.com");
        assertThat(detail.getAgentVersion()).isEqualTo("3.1.0");
        assertThat(detail.getAgentDescription()).isEqualTo("Full description");
        assertThat(detail.getStatus()).isEqualTo("PENDING");
        assertThat(detail.getTrustLevel()).isEqualTo("MEDIUM");
        assertThat(detail.getEndpoints()).isEmpty();
    }
}
