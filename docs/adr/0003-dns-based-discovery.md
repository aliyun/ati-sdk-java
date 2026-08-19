---
status: accepted
---

# DNS-based agent discovery with dual-hostname model

Agent discovery uses DNS TXT records at `_ati.{identityHost}` on the agent's **Identity Hostname**, replacing the RA OpenAPI (`DescribeAtiAgentRegisterInfoMarket`) path entirely.

Shared platforms (e.g. 百炼, Coze) use a **Dual Hostname Model**:

- **Identity Hostname** (`agentHost`) — registration anchor, Identity Certificate, `_ati` / `_ati-badge` / `_ati-identity._tls` DNS. A first-level subdomain of Access Hostname (e.g. `abc123.bailian.aliyun.com` under `bailian.aliyun.com`).
- **Access Hostname** — TLS landing zone, public Server Certificate, `_443._tcp` TLSA. Endpoint URLs (`u=` in TXT) point here (e.g. `https://bailian.aliyun.com/agents/abc123/mcp`).

**Single-hostname deployment** (one agent独占 a domain): Identity Hostname equals Access Hostname (e.g. both `agent.example.com`). RA registration requires `agentHost` to equal the `u=` host.

**Shared platform**: RA registration requires `agentHost` to be a **first-level subdomain** of the `u=` host (Access Hostname) — e.g. `abc123.bailian.aliyun.com` under `bailian.aliyun.com`.

Discovery TXT format: `v=ati1; av={version}; p={protocol}; u={url}` with optional `m=direct` (default `direct`). One TXT per protocol; `av` matched client-side via SemVer (semver4j); latest matching version wins. KV parse rules (order, keys, `p` enum, `av` prefix) are in ADR-0006 and `CONTEXT.md`.

`AgentDetail` from Discovery includes `agentHost`, `accessHost`, `agentVersion`, and `endpoints` only — not `agentId`, `status`, or `trustLevel` (RA/TL concepts).

Connection flow: `discover(identityHost)` → pick endpoint by `agentUrl` (`u=`) → `connect(agentUrl, ConnectOptions)` with `identityHost` and `accessHost` populated for split Badge/DANE lookups.

Failures throw typed exceptions (`AtiNotFoundException`, etc.) — not null.

## Considered options

- **Keep RA OpenAPI Discovery** — rejected; requires AK/SK, couples discovery to Alibaba Cloud API availability, incompatible with DNS-first shared-platform deployment.
- **DNS `_ati` TXT + trust card HTTP fetch** — rejected; endpoint URL is embedded directly in `u=`, no card indirection needed for v1.
- **DNS `_ati` TXT with dual hostname** — accepted.

## Consequences

- Remove `tea-openapi` from `ati-sdk-discovery`; add `dnsjava` and `semver4j`.
- Spring `ati.sdk.discovery` drops AK/SK/endpoint configuration.
- `AtiDiscoveryClient` class name unchanged; implementation becomes DNS-only.
- Connection verification must use Identity Hostname for Badge and Access Hostname for transport DANE.
- README sequence diagrams and examples must be updated.
