package com.aliyun.ati.sdk.discovery;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import static org.assertj.core.api.Assertions.assertThat;

@EnabledIfEnvironmentVariable(named = "ALIBABA_CLOUD_ACCESS_KEY_ID", matches = ".+")
class AtiDiscoveryIntegrationTest {

    @Test
    void shouldDiscoverAgentByHost() throws Exception {
        AtiDiscoveryClient client = new AtiDiscoveryClient(
            "alidns.aliyuncs.com",
            System.getenv("ALIBABA_CLOUD_ACCESS_KEY_ID"),
            System.getenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET"));

        AgentDetail detail = client.discover("dns-test.aliyuncs.com");

        System.out.println("=== Discover by host ===");
        printDetail(detail);

        assertThat(detail).isNotNull();
        assertThat(detail.getAgentHost()).isEqualTo("dns-test.aliyuncs.com");
        assertThat(detail.getAgentId()).isNotBlank();
        assertThat(detail.getStatus()).isEqualTo("Active");
    }

    @Test
    void shouldDiscoverAgentByHostAndVersion() throws Exception {
        AtiDiscoveryClient client = new AtiDiscoveryClient(
            "alidns.aliyuncs.com",
            System.getenv("ALIBABA_CLOUD_ACCESS_KEY_ID"),
            System.getenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET"));

        AgentDetail detail = client.discover("dns-test.aliyuncs.com", "^1.0.0");

        System.out.println("=== Discover by host + ^1.0.0 ===");
        printDetail(detail);

        assertThat(detail).isNotNull();
        assertThat(detail.getAgentVersion()).startsWith("1.");
    }

    @Test
    void shouldReturnNullForNonexistentHost() throws Exception {
        AtiDiscoveryClient client = new AtiDiscoveryClient(
            "alidns.aliyuncs.com",
            System.getenv("ALIBABA_CLOUD_ACCESS_KEY_ID"),
            System.getenv("ALIBABA_CLOUD_ACCESS_KEY_SECRET"));

        AgentDetail detail = client.discover("nonexistent-agent.example.com");

        System.out.println("=== Nonexistent host ===");
        System.out.println("Result: " + detail);

        assertThat(detail).isNull();
    }

    private void printDetail(AgentDetail detail) {
        if (detail == null) {
            System.out.println("Not found");
            return;
        }
        System.out.println("agentId: " + detail.getAgentId());
        System.out.println("agentHost: " + detail.getAgentHost());
        System.out.println("agentVersion: " + detail.getAgentVersion());
        System.out.println("displayName: " + detail.getAgentDisplayName());
        System.out.println("status: " + detail.getStatus());
        System.out.println("trustLevel: " + detail.getTrustLevel());
        System.out.println("description: " + detail.getAgentDescription());
        if (detail.getEndpoints() != null) {
            for (AgentEndpoint ep : detail.getEndpoints()) {
                System.out.println("endpoint: protocol=" + ep.getProtocol()
                    + " url=" + ep.getAgentUrl()
                    + " transports=" + ep.getTransports()
                    + " metadata=" + ep.getMetadataUrl());
            }
        } else {
            System.out.println("endpoints: (none)");
        }
    }
}
