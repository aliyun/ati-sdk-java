---
status: accepted
---

# DNS-based agent discovery with Independent and Shared Domain Mode

Agent discovery uses DNS TXT records at `_ati.{identityHost}` on the agent's **Identity Hostname**, replacing the RA OpenAPI (`DescribeAtiAgentRegisterInfoMarket`) path entirely.

Two service modes:

- **Independent Domain Mode** — one agent owns a dedicated domain. Identity Hostname = Access Hostname (`identityHost` = `accessHost`). RA requires the Identity Hostname to equal the `u=` host (e.g. both `agent.example.com`).
- **Shared Domain Mode** — multiple agents share one Access Hostname; each agent's Identity Hostname is a **first-level subdomain** of that Access Hostname (the immediate parent). Example: Identity `abc123.bailian.aliyun.com`, Access `bailian.aliyun.com`, `u=https://bailian.aliyun.com/agents/abc123/mcp`.

Identity Hostname is the registration anchor, Identity Certificate, and `_ati` / `_ati-badge` / `_ati-identity._tls` DNS. Access Hostname is the TLS landing zone, public Server Certificate, and `_443._tcp` TLSA; endpoint URLs (`u=` in TXT) use this host.

Discovery TXT format: `v=ati1; av={version}; p={protocol}; u={url}` with optional `m=direct` (default `direct`). One TXT per protocol; `av` matched client-side via SemVer (semver4j); latest matching version wins. KV parse rules (order, keys, `p` enum, `av` prefix) are in ADR-0006 and `CONTEXT.md`.

`AgentDetail` from Discovery includes Identity Hostname (`getAgentHost()`), Access Hostname (`getAccessHost()`), `agentVersion`, and `endpoints` only — not `agentId`, `status`, or `trustLevel` (RA/TL concepts).

Connection flow: `discover(/* identityHost */)` → pick endpoint by `agentUrl` (`u=`) → `connect(agentUrl, ConnectOptions)` with `identityHost` and `accessHost` populated for split Badge/DANE lookups in Shared Domain Mode. The Java method remains `discover(agentHost)`; that parameter is the Identity Hostname.

Failures throw typed exceptions (`AtiNotFoundException`, etc.) — not null.

## Considered options

- **Keep RA OpenAPI Discovery** — rejected; requires AK/SK, couples discovery to Alibaba Cloud API availability, incompatible with DNS-first Shared Domain Mode.
- **DNS `_ati` TXT + trust card HTTP fetch** — rejected; endpoint URL is embedded directly in `u=`, no card indirection needed for v1.
- **DNS `_ati` TXT with Independent / Shared Domain Mode** — accepted. (Formerly described as a "dual-hostname model"; that name is avoided — it sounds like two distinct FQDNs are always required.)

## Consequences

- Remove `tea-openapi` from `ati-sdk-discovery`; add `dnsjava` and `semver4j`.
- Spring `ati.sdk.discovery` drops AK/SK/endpoint configuration.
- `AtiDiscoveryClient` class name unchanged; implementation becomes DNS-only.
- Connection verification must use Identity Hostname for Badge and Access Hostname for transport DANE.
- README presents two host concepts only: `identityHost` and `accessHost`. RA/TL JSON `agentHost` and `getAgentHost()` are the same value as `identityHost`, not a third hostname type.
