package com.aliyun.ati.sdk.discovery;

import com.aliyun.ati.sdk.exception.AtiNotFoundException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AtiDiscoveryClientTest {

    private static final String IDENTITY_HOST = "abc123.bailian.aliyun.com";
    private static final String MCP_URL = "https://bailian.aliyun.com/agents/abc123/mcp";
    private static final String A2A_URL = "https://bailian.aliyun.com/agents/abc123/a2a";

    @Test
    @DisplayName("discover should reject null agentHost")
    void discoverShouldRejectNullAgentHost() {
        AtiDiscoveryClient client = new AtiDiscoveryClient((TxtRecordLookup) dnsName -> List.of());

        assertThatThrownBy(() -> client.discover(null))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("agentHost");
    }

    @Test
    @DisplayName("discover with version should reject null agentHost")
    void discoverWithVersionShouldRejectNullAgentHost() {
        AtiDiscoveryClient client = new AtiDiscoveryClient((TxtRecordLookup) dnsName -> List.of());

        assertThatThrownBy(() -> client.discover(null, "^1.0.0"))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("agentHost");
    }

    @Test
    @DisplayName("discover should throw AtiNotFoundException when no TXT records")
    void discoverShouldThrowWhenNoTxtRecords() {
        AtiDiscoveryClient client = new AtiDiscoveryClient(dnsName -> List.of());

        assertThatThrownBy(() -> client.discover(IDENTITY_HOST))
            .isInstanceOf(AtiNotFoundException.class);
    }

    @Test
    @DisplayName("discover should throw AtiNotFoundException when all TXT records invalid")
    void discoverShouldThrowWhenAllRecordsInvalid() {
        AtiDiscoveryClient client = new AtiDiscoveryClient(dnsName -> List.of("invalid", "also-invalid"));

        assertThatThrownBy(() -> client.discover(IDENTITY_HOST))
            .isInstanceOf(AtiNotFoundException.class);
    }

    @Test
    @DisplayName("discover should query _ati.{identityHost}")
    void discoverShouldQueryCorrectDnsName() {
        AtiDiscoveryClient client = new AtiDiscoveryClient(dnsName -> {
            assertThat(dnsName).isEqualTo("_ati." + IDENTITY_HOST);
            return List.of(txt("1.0.0", "mcp", MCP_URL));
        });

        client.discover(IDENTITY_HOST);
    }

    @Test
    @DisplayName("discover should return latest version when no constraint")
    void discoverShouldReturnLatestVersion() {
        AtiDiscoveryClient client = new AtiDiscoveryClient(dnsName -> List.of(
            txt("1.0.0", "mcp", MCP_URL),
            txt("2.0.0", "a2a", A2A_URL)
        ));

        AgentDetail detail = client.discover(IDENTITY_HOST);

        assertThat(detail.getAgentHost()).isEqualTo(IDENTITY_HOST);
        assertThat(detail.getAgentVersion()).isEqualTo("2.0.0");
        assertThat(detail.getAccessHost()).isEqualTo("bailian.aliyun.com");
        assertThat(detail.getEndpoints()).hasSize(1);
        assertThat(detail.getEndpoints().get(0).getProtocol()).isEqualTo("A2A");
        assertThat(detail.getEndpoints().get(0).getAgentUrl()).isEqualTo(A2A_URL);
        assertThat(detail.getEndpoints().get(0).getTransports()).isEmpty();
    }

    @Test
    @DisplayName("discover should filter by version constraint")
    void discoverShouldFilterByVersionConstraint() {
        AtiDiscoveryClient client = new AtiDiscoveryClient(dnsName -> List.of(
            txt("1.0.0", "mcp", MCP_URL),
            txt("2.0.0", "a2a", A2A_URL)
        ));

        AgentDetail detail = client.discover(IDENTITY_HOST, "^1.0.0");

        assertThat(detail.getAgentVersion()).isEqualTo("1.0.0");
        assertThat(detail.getEndpoints()).hasSize(1);
        assertThat(detail.getEndpoints().get(0).getProtocol()).isEqualTo("MCP");
    }

    @Test
    @DisplayName("discover should throw when version constraint matches nothing")
    void discoverShouldThrowWhenVersionConstraintMatchesNothing() {
        AtiDiscoveryClient client = new AtiDiscoveryClient(dnsName -> List.of(txt("1.0.0", "mcp", MCP_URL)));

        assertThatThrownBy(() -> client.discover(IDENTITY_HOST, "^2.0.0"))
            .isInstanceOf(AtiNotFoundException.class);
    }

    @Test
    @DisplayName("discover with blank version should behave like no version")
    void discoverWithBlankVersionShouldBehaveLikeNoVersion() {
        AtiDiscoveryClient client = new AtiDiscoveryClient(dnsName -> List.of(
            txt("1.0.0", "mcp", MCP_URL),
            txt("2.0.0", "a2a", A2A_URL)
        ));

        AgentDetail detail = client.discover(IDENTITY_HOST, "   ");

        assertThat(detail.getAgentVersion()).isEqualTo("2.0.0");
    }

    @Test
    @DisplayName("discover should return multiple endpoints for same version")
    void discoverShouldReturnMultipleEndpointsForSameVersion() {
        AtiDiscoveryClient client = new AtiDiscoveryClient(dnsName -> List.of(
            txt("1.0.0", "mcp", MCP_URL),
            txt("1.0.0", "a2a", A2A_URL)
        ));

        AgentDetail detail = client.discover(IDENTITY_HOST);

        assertThat(detail.getEndpoints()).hasSize(2);
        assertThat(detail.getEndpoints())
            .extracting(AgentEndpoint::getProtocol)
            .containsExactlyInAnyOrder("MCP", "A2A");
    }

    private static String txt(String version, String protocol, String url) {
        return "v=ati1; av=" + version + "; p=" + protocol + "; u=" + url + "; m=direct";
    }
}
