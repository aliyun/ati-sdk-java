# ati-sdk-discovery

Agent discovery module — resolves agent information (host, version, endpoints) via the RA OpenAPI.

## Key Classes

- `AtiDiscoveryClient` — OpenAPI-based agent discovery client
- `AgentDetail` — Resolved agent registration record (host, version, endpoints, status)
- `AgentEndpoint` — Protocol-specific endpoint (`agentUrl`, `protocol`, `metadataUrl`)

## Usage

```java
AtiDiscoveryClient client = new AtiDiscoveryClient(
    "alidns.aliyuncs.com", accessKeyId, accessKeySecret);

AgentDetail agent = client.discover("agent.example.com", "1.0.0");
String agentUrl = agent.getEndpoints().get(0).getAgentUrl();
```

> Badge TXT and TLSA DNS lookups happen during Connection pre-verification, not in this module.

## Dependencies

- `ati-sdk-core`
- Alibaba Cloud tea-openapi (OpenAPI client)
