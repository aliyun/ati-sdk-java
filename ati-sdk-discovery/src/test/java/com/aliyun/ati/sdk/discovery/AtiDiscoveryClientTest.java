package com.aliyun.ati.sdk.discovery;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for {@link AtiDiscoveryClient}.
 *
 * <p>Since constructing a real client requires valid Alibaba Cloud credentials,
 * these tests focus on input validation and the single-arg discover overload.</p>
 */
class AtiDiscoveryClientTest {

    /**
     * Creates a client for testing. The endpoint/credentials are not used
     * for real API calls in these tests.
     */
    private AtiDiscoveryClient createClient() throws Exception {
        return new AtiDiscoveryClient(
            "alidns.aliyuncs.com",
            "test-access-key-id",
            "test-access-key-secret");
    }

    @Test
    @DisplayName("Should construct client with valid parameters")
    void shouldConstructClientWithValidParameters() throws Exception {
        AtiDiscoveryClient client = createClient();
        assertThat(client).isNotNull();
    }

    @Test
    @DisplayName("discover should reject null agentHost")
    void discoverShouldRejectNullAgentHost() throws Exception {
        AtiDiscoveryClient client = createClient();

        assertThatThrownBy(() -> client.discover(null))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("agentHost");
    }

    @Test
    @DisplayName("discover with version should reject null agentHost")
    void discoverWithVersionShouldRejectNullAgentHost() throws Exception {
        AtiDiscoveryClient client = createClient();

        assertThatThrownBy(() -> client.discover(null, "^1.0.0"))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("agentHost");
    }

    @Test
    @DisplayName("discover should return null when API call fails")
    void discoverShouldReturnNullWhenApiCallFails() throws Exception {
        // The test credentials won't work against the real API,
        // so the callApi will fail and discover() catches the exception
        AtiDiscoveryClient client = createClient();

        AgentDetail result = client.discover("nonexistent.agent.example.com");

        assertThat(result).isNull();
    }

    @Test
    @DisplayName("discover with version should return null when API call fails")
    void discoverWithVersionShouldReturnNullWhenApiCallFails() throws Exception {
        AtiDiscoveryClient client = createClient();

        AgentDetail result = client.discover(
            "nonexistent.agent.example.com", "^1.0.0");

        assertThat(result).isNull();
    }

    @Test
    @DisplayName("discover with null version should behave like single-arg discover")
    void discoverWithNullVersionShouldBehaveLikeSingleArgDiscover() throws Exception {
        AtiDiscoveryClient client = createClient();

        // Both should return null (API not reachable with test creds)
        AgentDetail result1 = client.discover("test.example.com");
        AgentDetail result2 = client.discover("test.example.com", null);

        assertThat(result1).isNull();
        assertThat(result2).isNull();
    }

    @Test
    @DisplayName("discover with blank version should behave like no version")
    void discoverWithBlankVersionShouldBehaveLikeNoVersion() throws Exception {
        AtiDiscoveryClient client = createClient();

        AgentDetail result = client.discover("test.example.com", "   ");

        assertThat(result).isNull();
    }
}
