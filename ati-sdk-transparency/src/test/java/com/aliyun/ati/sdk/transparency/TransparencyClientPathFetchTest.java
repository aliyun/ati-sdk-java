package com.aliyun.ati.sdk.transparency;

import com.aliyun.ati.sdk.transparency.scitt.TrustedDomainRegistry;
import com.github.tomakehurst.wiremock.junit5.WireMockRuntimeInfo;
import com.github.tomakehurst.wiremock.junit5.WireMockTest;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.stubFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.verify;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@WireMockTest
class TransparencyClientPathFetchTest {

    private static final String TEST_AGENT_ID = "6bf2b7a9-1383-4e33-a945-845f34af7526";
    private static final String TEST_TL_PATH = "/tl/agents/" + TEST_AGENT_ID;

    @BeforeAll
    static void setUpClass() {
        System.setProperty(TrustedDomainRegistry.TRUSTED_DOMAINS_PROPERTY,
            "tl.atiagent.cn,ati-tl.cnnic.cn,localhost");
    }

    @AfterAll
    static void tearDownClass() {
        System.clearProperty(TrustedDomainRegistry.TRUSTED_DOMAINS_PROPERTY);
    }

    @Test
    @DisplayName("Should request configured baseUrl plus extracted path, not a Badge TXT u= host")
    void shouldRequestConfiguredBaseUrlPlusPath(WireMockRuntimeInfo wmRuntimeInfo) {
        String baseUrl = wmRuntimeInfo.getHttpBaseUrl();
        stubFor(get(urlEqualTo(TEST_TL_PATH))
            .willReturn(aResponse()
                .withStatus(200)
                .withHeader("Content-Type", "application/json")
                .withBody("""
                    {
                      "status": "ACTIVE",
                      "schemaVersion": "ATI-TL-V1",
                      "payload": {
                        "agentName": "ati://v1.0.0.agent.example.com",
                        "agentHost": "agent.example.com",
                        "version": "1.0.0",
                        "agentId": "6bf2b7a9-1383-4e33-a945-845f34af7526",
                        "agentStatus": "ACTIVE"
                      }
                    }
                    """)));

        TransparencyClient client = TransparencyClient.builder()
            .baseUrl(baseUrl)
            .build();

        assertThat(client.getTransparencyLogByPath(TEST_TL_PATH).getStatus()).isEqualTo("ACTIVE");
        verify(getRequestedFor(urlEqualTo(TEST_TL_PATH)));
    }

    @Test
    @DisplayName("Should reject path traversal before sending HTTP")
    void shouldRejectPathTraversalBeforeHttp() {
        TransparencyClient client = TransparencyClient.builder()
            .baseUrl(TransparencyClient.CNNIC_BASE_URL)
            .build();

        assertThatThrownBy(() -> client.getTransparencyLogByPath("/tl/agents/../../admin"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("Path traversal");
    }
}
