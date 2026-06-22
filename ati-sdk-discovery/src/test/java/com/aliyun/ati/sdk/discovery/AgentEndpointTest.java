package com.aliyun.ati.sdk.discovery;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.ArrayList;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for {@link AgentEndpoint}.
 */
class AgentEndpointTest {

    @Test
    @DisplayName("Should have null fields by default")
    void shouldHaveNullFieldsByDefault() {
        AgentEndpoint endpoint = new AgentEndpoint();

        assertThat(endpoint.getProtocol()).isNull();
        assertThat(endpoint.getAgentUrl()).isNull();
        assertThat(endpoint.getMetadataUrl()).isNull();
        assertThat(endpoint.getTransports()).isNull();
    }

    @Test
    @DisplayName("Should set and get protocol")
    void shouldSetAndGetProtocol() {
        AgentEndpoint endpoint = new AgentEndpoint();
        endpoint.setProtocol("A2A");

        assertThat(endpoint.getProtocol()).isEqualTo("A2A");
    }

    @Test
    @DisplayName("Should set and get agentUrl")
    void shouldSetAndGetAgentUrl() {
        AgentEndpoint endpoint = new AgentEndpoint();
        endpoint.setAgentUrl("https://agent.example.com/a2a");

        assertThat(endpoint.getAgentUrl())
            .isEqualTo("https://agent.example.com/a2a");
    }

    @Test
    @DisplayName("Should set and get metadataUrl")
    void shouldSetAndGetMetadataUrl() {
        AgentEndpoint endpoint = new AgentEndpoint();
        endpoint.setMetadataUrl("https://agent.example.com/.well-known/agent.json");

        assertThat(endpoint.getMetadataUrl())
            .isEqualTo("https://agent.example.com/.well-known/agent.json");
    }

    @Test
    @DisplayName("Should set and get transports")
    void shouldSetAndGetTransports() {
        AgentEndpoint endpoint = new AgentEndpoint();
        List<String> transports = new ArrayList<>();
        transports.add("sse");
        transports.add("streamable-http");
        endpoint.setTransports(transports);

        assertThat(endpoint.getTransports())
            .containsExactly("sse", "streamable-http");
    }

    @Test
    @DisplayName("Should support empty transports list")
    void shouldSupportEmptyTransportsList() {
        AgentEndpoint endpoint = new AgentEndpoint();
        endpoint.setTransports(List.of());

        assertThat(endpoint.getTransports()).isEmpty();
    }

    @Test
    @DisplayName("toString should include protocol and agentUrl")
    void toStringShouldIncludeProtocolAndAgentUrl() {
        AgentEndpoint endpoint = new AgentEndpoint();
        endpoint.setProtocol("MCP");
        endpoint.setAgentUrl("https://mcp.example.com/sse");

        String str = endpoint.toString();

        assertThat(str).contains("MCP");
        assertThat(str).contains("https://mcp.example.com/sse");
    }

    @Test
    @DisplayName("toString should handle null fields gracefully")
    void toStringShouldHandleNullFields() {
        AgentEndpoint endpoint = new AgentEndpoint();

        String str = endpoint.toString();

        assertThat(str).contains("AgentEndpoint");
        assertThat(str).contains("null");
    }

    @Test
    @DisplayName("Should populate all fields together")
    void shouldPopulateAllFieldsTogether() {
        AgentEndpoint endpoint = new AgentEndpoint();
        endpoint.setProtocol("A2A");
        endpoint.setAgentUrl("https://agent.example.com/a2a");
        endpoint.setMetadataUrl("https://agent.example.com/.well-known/agent.json");
        endpoint.setTransports(List.of("sse", "streamable-http"));

        assertThat(endpoint.getProtocol()).isEqualTo("A2A");
        assertThat(endpoint.getAgentUrl())
            .isEqualTo("https://agent.example.com/a2a");
        assertThat(endpoint.getMetadataUrl())
            .isEqualTo("https://agent.example.com/.well-known/agent.json");
        assertThat(endpoint.getTransports()).hasSize(2);
    }

    @Test
    @DisplayName("Should allow overwriting transports")
    void shouldAllowOverwritingTransports() {
        AgentEndpoint endpoint = new AgentEndpoint();
        endpoint.setTransports(List.of("sse"));

        assertThat(endpoint.getTransports()).hasSize(1);

        endpoint.setTransports(List.of("streamable-http", "websocket"));

        assertThat(endpoint.getTransports())
            .containsExactly("streamable-http", "websocket");
    }
}
