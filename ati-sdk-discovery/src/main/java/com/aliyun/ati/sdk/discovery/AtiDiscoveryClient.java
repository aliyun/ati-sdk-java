package com.aliyun.ati.sdk.discovery;

import com.aliyun.teaopenapi.Client;
import com.aliyun.teaopenapi.models.Config;
import com.aliyun.teaopenapi.models.OpenApiRequest;
import com.aliyun.teaopenapi.models.Params;
import com.aliyun.teautil.models.RuntimeOptions;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;

/**
 * Client for discovering ATI agents via Alibaba Cloud OpenAPI.
 *
 * <p>This client queries the ATI agent registry to resolve agent details
 * by host and optional version constraint.</p>
 *
 * <p>Example usage:</p>
 * <pre>{@code
 * AtiDiscoveryClient client = new AtiDiscoveryClient(
 *     "alidns.aliyuncs.com",
 *     "your-access-key-id",
 *     "your-access-key-secret");
 *
 * // Discover agent by host
 * AgentDetail detail = client.discover("agent.example.com");
 *
 * // Discover agent by host and version
 * AgentDetail detail = client.discover("agent.example.com", "^1.0.0");
 * }</pre>
 */
public final class AtiDiscoveryClient {

    private static final Logger LOG = LoggerFactory.getLogger(AtiDiscoveryClient.class);
    private static final String API_VERSION = "2015-01-09";
    private static final String ACTION = "DescribeAtiAgentRegisterInfoMarket";

    private final Client openApiClient;
    private final String endpoint;

    /**
     * Creates a new discovery client.
     *
     * @param endpoint the Alibaba Cloud API endpoint
     * @param accessKeyId the access key ID
     * @param accessKeySecret the access key secret
     * @throws Exception if the client cannot be created
     */
    public AtiDiscoveryClient(String endpoint,
                              String accessKeyId,
                              String accessKeySecret) throws Exception {
        Config config = new Config();
        config.setAccessKeyId(accessKeyId);
        config.setAccessKeySecret(accessKeySecret);
        config.setEndpoint(endpoint);
        config.setProtocol("HTTPS");
        this.endpoint = endpoint;
        this.openApiClient = new Client(config);
    }

    /**
     * Discovers an agent by host and optional version constraint.
     *
     * @param agentHost the agent FQDN (required)
     * @param agentVersion SemVer range expression (optional, e.g. "^1.0.0")
     * @return the agent detail, or null if not found
     */
    public AgentDetail discover(String agentHost, String agentVersion) {
        Objects.requireNonNull(agentHost, "agentHost must not be null");
        LOG.debug("[Discovery] Step 1/4: Resolving agent host '{}' (version='{}')", agentHost, agentVersion);
        try {
            Params params = new Params()
                .setAction(ACTION)
                .setVersion(API_VERSION)
                .setProtocol("HTTPS")
                .setMethod("POST")
                .setAuthType("AK")
                .setStyle("RPC")
                .setPathname("/")
                .setReqBodyType("json")
                .setBodyType("json");

            Map<String, Object> queries = new HashMap<>();
            queries.put("AgentHost", agentHost);
            if (agentVersion != null && !agentVersion.isBlank()) {
                queries.put("AgentVersion", agentVersion);
            }

            LOG.debug("[Discovery] Step 2/4: Calling OpenAPI endpoint='{}' action='{}', version='{}', queries={}",
                endpoint, ACTION, API_VERSION, queries);

            OpenApiRequest request = new OpenApiRequest().setQuery(
                com.aliyun.openapiutil.Client.query(queries));

            @SuppressWarnings("unchecked")
            Map<String, Object> response = (Map<String, Object>) openApiClient.callApi(
                params, request, new RuntimeOptions());

            LOG.debug("[Discovery] Step 3/4: Received response for {}: {}", agentHost, response);

            AgentDetail detail = parseResponse(response);
            if (detail != null) {
                LOG.debug("[Discovery] Step 4/4: Parsed agent detail — id='{}', host='{}', version='{}', endpoints={}",
                    detail.getAgentId(), detail.getAgentHost(), detail.getAgentVersion(),
                    detail.getEndpoints() != null ? detail.getEndpoints().size() : 0);
            } else {
                LOG.debug("[Discovery] Step 4/4: Parsed result is null (agent not registered or empty response)");
            }
            return detail;
        } catch (Exception e) {
            LOG.error("[Discovery] Failed to discover agent: {}", agentHost, e);
            return null;
        }
    }

    /**
     * Discovers an agent by host, returning the latest version.
     *
     * @param agentHost the agent FQDN (required)
     * @return the agent detail, or null if not found
     */
    public AgentDetail discover(String agentHost) {
        return discover(agentHost, null);
    }

    @SuppressWarnings("unchecked")
    private AgentDetail parseResponse(Map<String, Object> response) {
        if (response == null) {
            return null;
        }

        Map<String, Object> body = (Map<String, Object>) response.get("body");
        if (body == null) {
            return null;
        }

        // RPC style: data is directly in body, no Success/Data wrapper
        String agentId = (String) body.get("AgentId");
        if (agentId == null || agentId.isBlank()) {
            return null;
        }

        AgentDetail detail = new AgentDetail();
        detail.setAgentId(agentId);
        detail.setAgentDisplayName((String) body.get("AgentDisplayName"));
        detail.setAgentHost((String) body.get("AgentHost"));
        detail.setAgentVersion((String) body.get("AgentVersion"));
        detail.setAgentDescription((String) body.get("AgentDescription"));
        detail.setStatus((String) body.get("Status"));
        detail.setTrustLevel((String) body.get("TrustLevel"));

        // Endpoints structure: {Endpoint=[{AgentUrl=..., Protocol=..., Transports={Transport=[...]}}]}
        Map<String, Object> endpointsWrapper =
            (Map<String, Object>) body.get("Endpoints");
        if (endpointsWrapper != null) {
            List<Map<String, Object>> endpointsList =
                (List<Map<String, Object>>) endpointsWrapper.get("Endpoint");
            if (endpointsList != null) {
                List<AgentEndpoint> endpoints = new ArrayList<>();
                for (Map<String, Object> ep : endpointsList) {
                    AgentEndpoint endpoint = new AgentEndpoint();
                    endpoint.setProtocol((String) ep.get("Protocol"));
                    endpoint.setAgentUrl((String) ep.get("AgentUrl"));
                    endpoint.setMetadataUrl((String) ep.get("MetadataUrl"));
                    // Transports: {Transport=[STREAMABLE-HTTP]}
                    Map<String, Object> transportsWrapper =
                        (Map<String, Object>) ep.get("Transports");
                    if (transportsWrapper != null) {
                        List<String> transports =
                            (List<String>) transportsWrapper.get("Transport");
                        endpoint.setTransports(
                            transports != null ? transports : List.of());
                    }
                    endpoints.add(endpoint);
                }
                detail.setEndpoints(endpoints);
            }
        }

        return detail;
    }
}
