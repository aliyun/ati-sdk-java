# ati-sdk-discovery

Agent discovery module — resolves agent information via DNS `_ati` TXT records on the Identity Hostname.

## Key Classes

- `AtiDiscoveryClient` — DNS TXT-based agent discovery client
- `AgentDetail` — Discovery result (`agentHost`, `accessHost`, `agentVersion`, `endpoints`)
- `AgentEndpoint` — Protocol-specific endpoint (`agentUrl`, `protocol`)
- `AtiDiscoveryRecord` — Parsed `_ati` TXT record (`v`, `av`, `p`, `u`, `m`)

## Discovery TXT sample

`_ati.{agentHost}` — semicolon-separated KV; this SDK parses **`ati1`** only. One record per Protocol:

```
_ati.abc123.bailian.aliyun.com.  TXT  "v=ati1; av=v1.0.0; p=mcp; u=https://bailian.aliyun.com/agents/abc123/mcp"
_ati.abc123.bailian.aliyun.com.  TXT  "v=ati1; av=v1.0.0; p=a2a; u=https://bailian.aliyun.com/agents/abc123/a2a"
```

`p=` is lowercase `mcp`, `a2a`, or `http-api`. Optional `m=direct` (default when omitted).

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
