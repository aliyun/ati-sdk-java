# ati-sdk-discovery

Agent discovery module — resolves agent information via DNS `_ati` TXT records on the Identity Hostname.

## Key Classes

- `AtiDiscoveryClient` — DNS TXT-based agent discovery client
- `AgentDetail` — Discovery result (`agentHost`, `accessHost`, `agentVersion`, `endpoints`)
- `AgentEndpoint` — Protocol-specific endpoint (`agentUrl`, `protocol`)
- `AtiDiscoveryRecord` — Parsed `_ati` TXT record (`v`, `av`, `p`, `u`, `m`)

## Usage

```java
AtiDiscoveryClient client = new AtiDiscoveryClient();

// Discover by Identity Hostname (optional SemVer constraint)
// Shared platform: agentHost (identity) is a first-level subdomain of u= host (access)
AgentDetail agent = client.discover("abc123.bailian.aliyun.com", "^1.0.0");
String agentUrl = agent.getEndpoints().get(0).getAgentUrl();

// Connect with dual-hostname verification
AgentConnection conn = atiClient.connect(agentUrl,
    ConnectOptions.builder()
        .identityHost(agent.getAgentHost())
        .accessHost(agent.getAccessHost())
        .verificationPolicy(VerificationPolicy.ENHANCED)
        .build());
```

> Badge TXT and transport TLSA lookups happen during Connection pre-verification on the Identity and Access hostnames respectively — not in this module.

## Dependencies

- `ati-sdk-core`
- dnsjava
- semver4j
