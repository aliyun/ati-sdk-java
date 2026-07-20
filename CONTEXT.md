# ATI Java SDK

Java SDK for Agent Trust Infrastructure (ATI) — secure agent-to-agent communication with registry-based discovery, transparency log attestation, and configurable verification policies.

Scope: `ati-sdk-*` modules only. The `ans-sdk-java/` tree is a separate GoDaddy ANS SDK and is out of scope for this glossary.

## Language

**Agent**:
An AI intelligent agent (智能体) that registers in the RA and exposes one or more endpoints for other agents to connect to.
_Avoid_: Service, bot, assistant (when referring to an ATI-registered entity)

**Client Agent**:
An agent that initiates a connection to another agent — the calling party in an agent-to-agent interaction. An agent may act as client agent in one interaction and server agent in another.
_Avoid_: Client (alone — ambiguous with HTTP client or SDK client)

**Server Agent**:
An agent that accepts incoming connections from other agents — the called party in an agent-to-agent interaction. An agent may act as server agent in one interaction and client agent in another.
_Avoid_: Server (alone — ambiguous with HTTP server or host machine)

**Endpoint**:
A protocol-specific service surface published by an agent — e.g. MCP or A2A — identified by an `agentUrl` in the registry record.
_Avoid_: URL (alone), API (when the protocol is MCP or A2A)

**RA (Registration Authority)**:
The authoritative system that manages agent registration and lifecycle. In this SDK, Alibaba Cloud ATI service is the RA.
_Avoid_: Registry (alone — too generic), Console (RA is the service; Console is just one interface to it)

**ATI Console**:
The RA's web UI for registering agents, completing ACME/DNS verification, and managing lifecycle.
_Avoid_: Portal, dashboard

**Discovery**:
Querying the RA's OpenAPI to resolve a registered agent's details (host, version, endpoints, badge URL) by `agentHost` and optional version constraint.
_Avoid_: DNS lookup (alone — discovery goes through OpenAPI, not direct DNS resolution of agent records)

**Connection**:
Establishing a verified TLS link to an agent's endpoint URL — running pre-verification (Badge/DANE), TLS handshake, and post-verification (fingerprint comparison). Does not require prior Discovery; can connect directly to a known `agentUrl`.
_Avoid_: Session (alone — ambiguous with HTTP session), link (too vague)

**Server Certificate**:
The TLS certificate a server agent uses to serve HTTPS — proves the server's identity to connecting clients. User-provided or ACME-issued; not signed by ATI.
_Avoid_: Service cert (prefer Server Certificate), TLS cert (alone — ambiguous with client-side TLS material)

**Identity Certificate**:
An ATI-issued, privately signed certificate that proves an agent's identity in mTLS. Every registered agent receives one at registration, regardless of role. Used when an agent acts as client agent (presented on outbound connections) and verified when an agent acts as server agent (checking the caller's identity). Carries the agent's ATI Name in the URI SAN (`ati://v{version}.{agentHost}`).
_Avoid_: Client cert (alone — ambiguous with any mTLS client certificate), mTLS cert

### Trust & Verification

**Badge**:
A registration credential issued by the RA for an agent, stored in the Transparency Log and discoverable via the DNS TXT record `_ati-badge.{agentHost}`. Badge verification confirms an agent is legitimately registered and binds certificate fingerprints to the registry record.
_Avoid_: Token, credential (alone — too generic)

**Transparency Log (TL)**:
The append-only public log where Badges are stored. Only CNNIC operates the TL service for ATI (default: `ati-tl.cnnic.cn:8180`; legacy: `tl.atiagent.cn`). Verification fetches the Badge entry, validates the Seal signature and Merkle proof, and compares certificate fingerprints.
_Avoid_: TL (alone — spell out on first use), audit log, Alibaba Cloud TL (TL is CNNIC-operated, not Alibaba Cloud)

**Verification Policy**:
The trust verification level applied when establishing an agent-to-agent connection. Policies are progressive — each level includes all checks from the previous level.

- **PKI Only** (`PKI_ONLY`) — 基础认证: standard TLS with system CA validation only.
- **Badge Required** (`BADGE_REQUIRED`) — 增强认证: PKI + Badge verification via the Transparency Log. Recommended production default.
- **DANE and Badge** (`DANE_AND_BADGE`) — 最高认证: PKI + Badge + DANE TLSA verification. Requires DNSSEC infrastructure.
_Avoid_: Security level (alone), trust mode (prefer Verification Policy)

### Identity

**agentHost**:
The FQDN that uniquely identifies an agent in the RA — e.g. `agent.example.com`. Used as the primary key for Discovery queries.
_Avoid_: hostname (alone — ambiguous with machine hostname), domain (too vague)

**ATI Name**:
The canonical URI identifier for an agent, including version: `ati://v{version}.{agentHost}`. Embedded in the Identity Certificate's URI SAN.
_Avoid_: agent URI (prefer ATI Name), ANS name (out of scope — ANS uses `ans://`)

**DANE**:
DNS-based Authentication of Named Entities — verification that a presented certificate or public key matches a DNSSEC-secured TLSA record published for the agent's domain.
_Avoid_: DNS verification (alone — too broad), certificate pinning (different mechanism)

**TLSA Record**:
A DNS record binding a domain to an expected certificate or public key fingerprint. Server agents publish under `_443._tcp.{agentHost}`; identity certificates publish under `_ati-identity._tls.{agentHost}`. These prefixes must not be mixed.
_Avoid_: DNS record (alone), TLS record
