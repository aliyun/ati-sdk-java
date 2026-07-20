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

**Agent Lifecycle Status**:
The registration state of an agent in the RA, following the state machine: `PENDING` → `PENDING_DNS` → `ACTIVE` → `DEPRECATED` → `REVOKED`.

- `PENDING` — registration in progress, verification not yet complete.
- `PENDING_DNS` — awaiting DNS record verification (TLSA, Badge TXT).
- `ACTIVE` — fully registered, discoverable, and safe for production connections.
- `DEPRECATED` — still connectable with a warning; callers should migrate to a newer version.
- `REVOKED` — registration revoked; connections must be rejected.
_Avoid_: status (alone), agent state (prefer Agent Lifecycle Status)

**Registration Status**:
The status field on a TL Badge entry, used during Badge verification to decide pass/reject. Related to but not identical to Agent Lifecycle Status. Badge verification additionally recognizes:
- `WARNING` — passes with a warning (treated like `ACTIVE`).
- `EXPIRED` — rejected (treated like `REVOKED`).
_Avoid_: badge status (prefer Registration Status when referring to TL entries)

**Protocol**:
The communication protocol declared on an Endpoint. Discovery returns one or more Endpoints per agent; the client agent selects the appropriate Protocol to connect. An agent may publish multiple Endpoints, each with a different Protocol.
_Avoid_: transport (too vague), API type

**HTTP-API**:
Standard REST/HTTP interface exposed by an agent endpoint. Used with the SDK's `HttpApiClient` for request/response calls.
_Avoid_: REST (alone — HTTP-API is the ATI protocol name), HTTP (alone)

**A2A**:
Agent-to-Agent protocol — a dedicated inter-agent communication protocol exposed as an Endpoint.
_Avoid_: agent protocol (too vague)

**MCP**:
Model Context Protocol — an endpoint protocol for tool invocation, resource access, and prompt exchange between agents.
_Avoid_: model protocol, MCP server (MCP is the protocol; the agent is still an Agent)

**agentUrl**:
The connectable HTTPS URL of an Endpoint — e.g. `https://agent.example.com/mcp`. The target address for Connection after Discovery selects an Endpoint.
_Avoid_: URL (alone), endpoint URL (prefer agentUrl — matches the RA field name)

**metaDataUrl**:
An optional URL on an Endpoint pointing to the agent's capability metadata (e.g. an Agent Card or service descriptor). Not used for TLS connection — informational only.
_Avoid_: metadata endpoint, description URL

**Agent Card**:
A self-published metadata document describing an agent's capabilities, skills, and interfaces — typically JSON, often used with the A2A protocol. Discovered via an Endpoint's `metaDataUrl`. Complements AgentDetail: AgentDetail answers who is registered and where to connect; Agent Card answers what the agent can do after connecting. Does not participate in Badge/DANE trust verification.
_Avoid_: agent metadata (too vague), capability descriptor (prefer Agent Card when referring to A2A-style documents)

**RA (Registration Authority)**:
The authoritative system that manages agent registration and lifecycle. In this SDK, Alibaba Cloud ATI service is the RA.
_Avoid_: Registry (alone — too generic), Console (RA is the service; Console is just one interface to it)

**ATI Console**:
The RA's web UI for registering agents, completing ACME/DNS verification, and managing lifecycle.
_Avoid_: Portal, dashboard

**ACME Verification**:
The registration-phase domain ownership proof — adding a DNS TXT challenge record to demonstrate control of the agentHost. Part of the RA registration flow, not performed by the SDK.
_Avoid_: domain validation (too vague), Let's Encrypt (ACME is the protocol; ATI uses it for ownership proof)

**DNS Verification**:
The final registration-phase step — adding TLSA and Badge TXT DNS records so the agent becomes `ACTIVE`. Distinct from Badge/DANE verification at Connection time.
_Avoid_: DNS check (too vague), record verification (ambiguous with Connection-time DANE)

**Discovery**:
Querying the RA's OpenAPI to resolve a registered agent's details (host, version, endpoints, badge URL) by `agentHost` and optional version constraint.
_Avoid_: DNS lookup (alone — discovery goes through OpenAPI, not direct DNS resolution of agent records)

**AgentDetail**:
The result returned by Discovery — a snapshot of an agent's RA registration record, including `agentId`, `agentHost`, `agentVersion`, `status`, `trustLevel`, and `endpoints`. Used by a client agent to select an Endpoint and initiate a Connection. The SDK also uses the name `AgentDetails` in some modules for the same concept.
_Avoid_: agent record (too vague), discovery response (prefer AgentDetail)

**trustLevel**:
A trust rating assigned by the RA to an agent (e.g. `HIGH`, `MEDIUM`), returned in AgentDetail. Informational — it does not automatically change the client agent's Verification Policy choice.
_Avoid_: trust score, security level (prefer trustLevel — matches the RA field name)

**Connection**:
Establishing a verified TLS link to an agent's endpoint URL — running pre-verification (Badge/DANE), TLS handshake, and post-verification (fingerprint comparison). Does not require prior Discovery; can connect directly to a known `agentUrl`. Encompasses Server Verification when initiated by a client agent.
_Avoid_: Session (alone — ambiguous with HTTP session), link (too vague)

**Server Verification**:
Client-side verification of a target server agent during Connection, governed by Verification Policy. Runs Pre-verification (Badge/DANE expectations from DNS and TL) and Post-verification (compare captured Server Certificate fingerprint). Symmetric counterpart to Client Verification.
_Avoid_: server-side verification (ambiguous — that is Client Verification), outbound verification (too vague)

**mTLS (Mutual TLS)**:
A TLS connection where both parties may present certificates — the server agent presents its Server Certificate, the client agent may present its Identity Certificate. Client-side connections typically use mTLS; server-side acceptance of client Identity Certificates depends on IDCA configuration. Pre/Post-verification (Badge/DANE) runs on top of the TLS layer.
_Avoid_: two-way TLS (prefer mTLS), client-auth (implementation detail, not the domain concept)

**Server Certificate**:
The TLS certificate a server agent uses to serve HTTPS — proves the server's identity to connecting clients. User-provided or ACME-issued; not signed by ATI.
_Avoid_: Service cert (prefer Server Certificate), TLS cert (alone — ambiguous with client-side TLS material)

**Identity Certificate**:
An ATI-issued, privately signed certificate that proves an agent's identity in mTLS. Every registered agent receives one at registration, regardless of role. Used when an agent acts as client agent (presented on outbound connections). Server-side validation of a caller's Identity Certificate requires IDCA to be configured on the server agent; without IDCA, client identity certificate verification is not performed. Carries the agent's ATI Name in the URI SAN (`ati://v{version}.{agentHost}`).
_Avoid_: Client cert (alone — ambiguous with any mTLS client certificate), mTLS cert

### Trust & Verification

**Badge**:
A registration credential issued by the RA for an agent, stored in the Transparency Log and discoverable via the DNS TXT record `_ati-badge.{agentHost}`. Badge verification confirms an agent is legitimately registered and binds certificate fingerprints to the registry record. Badge TXT lookup does not require DNSSEC.
_Avoid_: Token, credential (alone — too generic)

**Seal**:
The cryptographic signature on a Badge entry in the Transparency Log, verifiable against the TL root public key during pre-verification.
_Avoid_: Signature (alone — too generic)

**Merkle Proof**:
Evidence that a Badge entry exists in the TL's append-only Merkle tree, preventing forgery or tampering. Validated alongside the Seal during Badge pre-verification.
_Avoid_: Proof (alone), hash chain

**Transparency Log (TL)**:
The append-only public log where Badges are stored. Only CNNIC operates the TL service for ATI (default: `ati-tl.cnnic.cn:8180`; legacy: `tl.atiagent.cn`). Verification fetches the Badge entry, validates the Seal signature and Merkle proof, and compares certificate fingerprints.
_Avoid_: TL (alone — spell out on first use), audit log, Alibaba Cloud TL (TL is CNNIC-operated, not Alibaba Cloud)

**Verification Policy**:
The trust verification level applied when establishing an agent-to-agent connection. Policies are progressive — each level includes all checks from the previous level.

- **PKI Only** (`PKI_ONLY`) — 基础认证: standard TLS with system CA validation only.
- **Badge Required** (`BADGE_REQUIRED`) — 增强认证: PKI + Badge verification via the Transparency Log. Recommended production default.
- **DANE and Badge** (`DANE_AND_BADGE`) — 最高认证: PKI + Badge + DANE TLSA verification. Requires DNSSEC infrastructure.
_Avoid_: Security level (alone), trust mode (prefer Verification Policy)

**Pre-verification**:
The phase before the TLS handshake that asynchronously gathers verification expectations — DANE TLSA hashes and/or Badge fingerprints from DNS and the Transparency Log. Does not require the server's certificate yet.
_Avoid_: Pre-check (too vague), upfront validation

**Post-verification**:
The phase after the TLS handshake that synchronously compares the captured server certificate against the expectations collected during pre-verification. Fails the connection if fingerprints do not match.
_Avoid_: Post-check (too vague), cert validation (ambiguous with PKI)

**Certificate Fingerprint**:
The SHA-256 hash of a certificate, formatted as `SHA256:{hex}`. Used in post-verification to confirm the presented certificate matches the value recorded in the TL Badge entry.

- **Server Cert Fingerprint** — fingerprint of the Server Certificate; compared during client-side post-verification of a server agent.
- **Identity Cert Fingerprint** — fingerprint of the Identity Certificate; compared during server-side verification of a client agent.
_Avoid_: cert hash (prefer Certificate Fingerprint), thumbprint (ambiguous with X.509 thumbprint format)

**IDCA (Identity CA)**:
The private certificate authority used by ATI to issue Identity Certificates. Distinct from public CAs used for Server Certificates. Optional on server agents — configuring `idca.trust-certificate` enables mTLS client Identity Certificate chain validation; omitting IDCA skips client identity certificate verification to reduce integration complexity.
_Avoid_: CA (alone — ambiguous with public CA or Server Certificate issuer), root CA

**Client Verification**:
Server-side verification of an incoming client agent, governed jointly by **Verification Policy** and **IDCA** configuration. When IDCA is configured, the server agent validates the caller's Identity Certificate chain (IDCA) and applies Badge/DANE checks per Verification Policy — extracting the caller's ATI Name from the certificate URI SAN, then verifying via `_ati-badge` TXT + TL (Badge) and optionally `_ati-identity._tls` TLSA (DANE). When IDCA is not configured, client identity certificate verification is not performed. Does not rely on SCITT headers.
_Avoid_: client auth (too vague), inbound verification (prefer Client Verification)

**SCITT Header**:
HTTP headers carrying Transparency Log artifacts (Receipt, Status Token) for auditable attestation. Planned capability — **not supported in the current SDK version**; may be added in a future release. When supported, a client agent would attach its own SCITT artifacts to outgoing requests. Server-side client verification in ATI does not rely on SCITT headers — it uses Identity Certificate + Badge + DANE instead.
_Avoid_: Transparency header (prefer SCITT Header), SCITT (alone — spell out on first use)

### Identity

**agentHost**:
The FQDN that uniquely identifies an agent in the RA — e.g. `agent.example.com`. Used as the primary key for Discovery queries.
_Avoid_: hostname (alone — ambiguous with machine hostname), domain (too vague)

**agentId**:
The unique registration ID assigned by the RA to an agent (UUID), returned in AgentDetail and stored in TL Badge entries. Identifies a specific registration record within RA/TL systems. Distinct from agentHost (a host may have multiple agentIds during version rotation) and from ATI Name (the URI embedded in the Identity Certificate).
_Avoid_: agent UUID (prefer agentId — matches the RA field name), ATI Name (different identifier)

**ATI Name**:
The canonical URI identifier for an agent, including version: `ati://v{version}.{agentHost}`. Embedded in the Identity Certificate's URI SAN.
_Avoid_: agent URI (prefer ATI Name), ANS name (out of scope — ANS uses `ans://`)

**agentVersion**:
The SemVer version of an agent as recorded in the RA registration — e.g. `1.0.0`. Also embedded in the ATI Name and optionally in Badge DNS TXT records during version rotation.
_Avoid_: version (alone — ambiguous with version constraint or ATI Name prefix)

**Version Constraint**:
A SemVer matching expression passed to Discovery — e.g. `1.0.0` (exact), `^1.0.0` (compatible), `~1.2.0` (approximate), `*` (latest). Resolved server-side by the RA OpenAPI.
_Avoid_: version filter, semver query

**Version Rotation**:
The coexistence of multiple agentVersion values under the same agentHost during upgrades. DNS may hold multiple Badge TXT records (each tagged with `version=`), and the TL may hold multiple Badge entries. Discovery selects a version via Version Constraint; Badge pre-verification accepts any matching fingerprint.
_Avoid_: version upgrade (too vague), rolling update

**DANE**:
DNS-based Authentication of Named Entities — verification that a presented certificate or public key matches a TLSA record published for the agent's domain. TLSA records are validated with DNSSEC during DANE verification.
_Avoid_: DNS verification (alone — too broad), certificate pinning (different mechanism)

**DNSSEC**:
DNS Security Extensions — cryptographic signing of DNS responses (DNSKEY/RRSIG) to prevent tampering. Required only for DANE TLSA verification, not for Badge TXT lookup. Badge pre-verification reads `_ati-badge` TXT records and validates entries via the Transparency Log (Seal + Merkle Proof) without requiring DNSSEC.
_Avoid_: DNS security (too vague), DNS signing (implementation detail)

**TLSA Record**:
A DNS record binding a domain to an expected certificate or public key fingerprint. Server agents publish under `_443._tcp.{agentHost}`; identity certificates publish under `_ati-identity._tls.{agentHost}`. These prefixes must not be mixed.
_Avoid_: DNS record (alone), TLS record
