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
A protocol-specific service surface published by an agent — identified by `agentUrl` (the `u=` value from Discovery TXT), a **Protocol** (`p=` in TXT, e.g. `mcp`, `a2a`), and optional **Transport** list. After DNS Discovery, each endpoint's `agentUrl` is the direct connect target — the URL path typically encodes the protocol (e.g. `.../mcp`, `.../a2a`); callers select an endpoint by `agentUrl`, not by passing a separate protocol argument to connect.
_Avoid_: URL (alone), API (when the protocol is MCP or A2A)

**Agent Lifecycle Status**:
The registration state of an agent in the RA, following the state machine: `PENDING` → `PENDING_DNS` → `ACTIVE` → `DEPRECATED` → `REVOKED`.

- `PENDING` — registration in progress, verification not yet complete.
- `PENDING_DNS` — awaiting DNS record verification (TLSA, Badge TXT).
- `ACTIVE` — fully registered, discoverable, and safe for production connections.
- `DEPRECATED` — still connectable with a warning; callers should migrate to a newer version.
- `REVOKED` — registration revoked; connections must be rejected.

Returned as `status` on RA registration records. TL Badge Entry payload may also carry a snapshot as `payload.agentStatus` — semantically related, but Connection verification uses TL top-level **Registration Status**, not RA lifecycle status or `payload.agentStatus`. Not available from DNS Discovery.
_Avoid_: status (alone), agent state (prefer Agent Lifecycle Status)

**Registration Status**:
The top-level `status` field on a TL Badge Entry, used during Badge verification to decide pass/reject. Related to but not identical to Agent Lifecycle Status. Badge verification additionally recognizes:
- `WARNING` — passes with a warning (treated like `ACTIVE`).
- `EXPIRED` — rejected (treated like `REVOKED`).

The SDK reads this via `TransparencyLog.getStatus()` — not `payload.agentStatus`, which is a lifecycle snapshot inside the payload that the verification logic does not use as the authority.
_Avoid_: badge status (prefer Registration Status when referring to TL entries), agentStatus (ambiguous — use Registration Status for TL top-level `status`, Agent Lifecycle Status for RA `AgentDetail.status`)

**Protocol**:
The communication protocol declared on an Endpoint — e.g. `MCP`, `A2A`, `HTTP-API`. Answers *what interface* to connect to. Discovery returns one or more Endpoints per agent; the client agent selects the appropriate Protocol to connect. An agent may publish multiple Endpoints, each with a different Protocol. Orthogonal to **Transport**, which declares the HTTP transport mode for a given Protocol.
_Avoid_: API type (prefer Protocol — matches RA field name)

**Transport**:
The HTTP transport mode declared on an Endpoint — e.g. `STREAMABLE-HTTP` for MCP. Answers *how* to carry the Protocol over HTTP. Not published in Discovery TXT records — `AgentEndpoint.transports` may be empty after Discovery; the client agent selects a transport implementation based on **Protocol** (e.g. `HttpClientStreamableHttpTransport` for MCP). Does not participate in Badge/DANE trust verification.
_Avoid_: transport layer (ambiguous with TLS), protocol (Transport is not Protocol)

**HTTP-API**:
Standard REST/HTTP interface exposed by an agent endpoint — one of the Endpoint **Protocol** values. Client agent SDK access: create via `AgentConnection.httpApiAt(agentUrl)` after `AtiClient.connect()`, which returns an `HttpApiClient` reusing the verified TLS connection for request/response calls.
_Avoid_: REST (alone — HTTP-API is the ATI protocol name), HTTP (alone)

**A2A**:
Agent-to-Agent protocol — a dedicated inter-agent communication protocol exposed as an Endpoint.
_Avoid_: agent protocol (too vague)

**MCP**:
Model Context Protocol — an endpoint protocol for tool invocation, resource access, and prompt exchange between agents.
_Avoid_: model protocol, MCP server (MCP is the protocol; the agent is still an Agent)

**agentUrl**:
The connectable HTTPS URL of an Endpoint — e.g. `https://bailian.aliyun.com/agents/{agentId}/mcp` on a shared platform, or `https://agent.example.com/mcp` in single-hostname mode. Published in Discovery TXT records as `u=`. The URL's host is the **Access Hostname**; the agent's **Identity Hostname** (`agentHost`) is typically a first-level subdomain on shared platforms (e.g. `abc123.bailian.aliyun.com` under `bailian.aliyun.com`). In **single-hostname mode**, RA requires the `u=` host to **equal** `agentHost`.
_Avoid_: URL (alone), endpoint URL (prefer agentUrl — matches the RA field name)

**metaDataUrl**:
An optional URL on an Endpoint pointing to the agent's capability metadata (e.g. an Agent Card or service descriptor). Not used for TLS connection — informational only. RA OpenAPI field name: `MetadataUrl`. The discovery module's `AgentEndpoint.metadataUrl` is the same field — use **metaDataUrl** in discussion, `getMetadataUrl()` when referencing discovery module Java code.
_Avoid_: metadata endpoint, description URL, metadataUrl (alone — prefer metaDataUrl unless citing discovery module field names)

**Agent Card**:
A self-published metadata document describing an agent's capabilities, skills, and interfaces — typically JSON, often used with the A2A protocol. Discovered via an Endpoint's `metaDataUrl`. Complements AgentDetail: AgentDetail answers who is registered and where to connect; Agent Card answers what the agent can do after connecting. Does not participate in Badge/DANE trust verification.
_Avoid_: agent metadata (too vague), capability descriptor (prefer Agent Card when referring to A2A-style documents)

**RA (Registration Authority)**:
The authoritative system that manages agent registration and lifecycle. In this SDK, Alibaba Cloud ATI service is the RA — providing ATI Console, endpoint metadata, and `trustLevel`. Distinct from CNNIC, which operates the trust infrastructure (Transparency Log and Identity Certificate issuance). Badge verification links the two: DNS `_ati-badge` on the Identity Hostname points to TL entries (CNNIC) that attest RA registration records. SDK Discovery does not call RA OpenAPI.
_Avoid_: Registry (alone — too generic), Console (RA is the service; Console is just one interface to it)

**CNNIC**:
China Internet Network Information Center — the national authority that operates ATI's trust infrastructure. Responsibilities include the Transparency Log (Badge storage, Seal, and Merkle Proof) and Identity Certificate issuance via IDCA. CNNIC commissions **UniTrust** to operate the **IDCA Root** and issues Identity Certificates from the **IDCA Intermediate**. Provides regulatory credibility for privately signed agent identity. Distinct from the RA (Alibaba Cloud ATI), which manages registration via Console.
_Avoid_: TL operator (alone — CNNIC also owns IDCA), CA provider (prefer CNNIC when referring to the institutional role)

**ATI Console**:
The RA's web UI for registering agents, completing ACME/DNS verification, and managing lifecycle.
_Avoid_: Portal, dashboard

**ACME Verification**:
The registration-phase domain ownership proof — adding a DNS TXT challenge record to demonstrate control of the agentHost. Part of the RA registration flow, not performed by the SDK.
_Avoid_: domain validation (too vague), Let's Encrypt (ACME is the protocol; ATI uses it for ownership proof)

**DNS Verification**:
The final registration-phase step — adding TLSA and Badge TXT DNS records so the agent becomes `ACTIVE`. Distinct from Badge/DANE verification at Connection time.
_Avoid_: DNS check (too vague), record verification (ambiguous with Connection-time DANE)

**Identity CSR**:
The certificate signing request submitted during RA registration to obtain an Identity Certificate. Must include the agent's ATI Name as a URI SAN (`ati://v{version}.{agentHost}`). CNNIC — the national regulatory authority — issues the resulting Identity Certificate from this CSR, operating the private identity CA that underpins ATI agent identity. Distinct from the Server Certificate, which is user-provided or ACME-issued. Completed via ATI Console, not by the SDK.
_Avoid_: client CSR (ambiguous), server CSR (that is for the Server Certificate)

**Discovery**:
Resolving a registered agent's endpoints by querying DNS TXT records at `_ati.{agentHost}` on the agent's **Identity Hostname**. Input is the Identity Hostname (agentHost) and an optional **Version Constraint**; the client filters matching TXT records, selects the **latest** matching `av` (agent version), and returns one `AgentDetail` with all protocol endpoints at that version. Does not call the RA OpenAPI. Does not query `_ati-badge` TXT — Badge lookup remains in Connection pre-verification only. Failures throw typed exceptions (e.g. no matching TXT, DNS lookup error) — does not return null.
_Avoid_: OpenAPI discovery, registry lookup (prefer Discovery — DNS TXT on Identity Hostname), DNS lookup (alone — specify `_ati` TXT discovery), null return (prefer typed exceptions on failure)

**Discovery TXT Record**:
A DNS TXT record at `_ati.{agentHost}` on the **Identity Hostname**, one record per protocol endpoint. Format: `v={format}; av={agentVersion}; p={protocol}; u={agentUrl}` with optional `m={mode}`.

- `v` — ATI discovery format version (currently `ati1` only).
- `av` — agent version (SemVer, e.g. `v1.0.0`); matched client-side against the **Version Constraint**. When multiple TXT records match, Discovery selects the **latest** matching `av` and returns all protocol (`p`) records at that version. When no Version Constraint is provided, Discovery selects the **latest** `av` among all records.
- `p` — **Protocol** in lowercase in TXT (e.g. `mcp`, `a2a`, `http-api`); the SDK normalizes to uppercase (`MCP`, `A2A`, `HTTP-API`) in `AgentEndpoint.protocol` to match existing conventions.
- `u` — full HTTPS service URL on the **Access Hostname** (e.g. `https://bailian.aliyun.com/agents/abc123/mcp` on a shared platform). In **single-hostname mode**, host equals `agentHost` (e.g. `https://agent.example.com/mcp`).
- `m` — optional **Discovery Mode** (currently only `direct` is supported). When omitted, defaults to `direct` — connect directly to the URL in `u`.

Multiple TXT records may coexist under the same Identity Hostname — one per protocol, and optionally multiple `av` values during **Version Rotation**.
_Avoid_: _ati-badge (that is Badge TXT, not Discovery TXT), trust card URL (Discovery embeds `u` directly — no separate card fetch)

**Discovery Mode**:
How Discovery resolves an endpoint from a Discovery TXT record. Currently only **`direct`** (`m=direct`) is supported — the client connects directly to the `u` URL. When `m` is omitted from the TXT record, `direct` is assumed. TXT records with an unsupported `m` value are skipped during Discovery; if no valid records remain, Discovery throws **AtiNotFoundException**. Future modes may be added without changing the `v=ati1` format version.
_Avoid_: mode (alone — prefer Discovery Mode), card mode (not supported in current SDK)

**AgentDetail**:
The result returned by DNS Discovery — includes `agentHost` (Identity Hostname), `accessHost` (Access Hostname, derived from the `u=` URL host — shared across all endpoints), `agentVersion`, and `endpoints` built from matching Discovery TXT records. Each endpoint carries its own `agentUrl` (`u=`); `accessHost` is duplicated at the top level for convenience (e.g. Transport DANE lookup in **ConnectOptions**). On shared platforms, `accessHost` differs from `agentHost`; in single-hostname mode they are equal. Does **not** include `agentId`, `status`, or `trustLevel` — those are RA/TL concepts unavailable via DNS Discovery. Exposed as `com.aliyun.ati.sdk.discovery.AgentDetail`.
_Avoid_: agent record (too vague), discovery response (prefer AgentDetail), OpenAPI registration snapshot (DNS Discovery returns a slimmer shape)

**trustLevel**:
A trust rating assigned by the RA to an agent (e.g. `HIGH`, `MEDIUM`). Informational — it does not automatically change the client agent's Verification Policy choice. Not available from DNS Discovery.
_Avoid_: trust score, security level (prefer trustLevel — matches the RA field name)

**Connection**:
Establishing a verified TLS link to an agent's endpoint URL on the **Access Hostname** — running pre-verification (Badge/DANE on the **Identity Hostname**), TLS handshake, and post-verification (fingerprint comparison). Under the **Dual Hostname Model**, the `agentUrl` host differs from the Identity Hostname used for Badge/DANE lookups. Does not require prior Discovery; can connect directly to a known `agentUrl` if `identityHost` is supplied via **ConnectOptions**. Encompasses Server Verification when initiated by a client agent.
_Avoid_: Session (alone — ambiguous with HTTP session), link (too vague)

**AtiClient**:
SDK client class for the simplified integration path — `connect(agentUrl, ConnectOptions)` returns an `AgentConnection` for HTTP-API request/response. Typical flow: `AtiDiscoveryClient.discover(agentHost)` → pick an endpoint by `agentUrl` (`u=` from TXT) → `connect(agentUrl, ConnectOptions)` with `identityHost` populated from `AgentDetail.agentHost`. Encapsulates Badge/DANE pre/post-verification internally. Not an Agent — it is the client agent's SDK entry point.
_Avoid_: ATI client (alone — ambiguous with any SDK module), client (alone)

**AtiVerifiedClient**:
SDK client class for advanced integration — configures mTLS keystore, `VerificationPolicy`, and optional `agentId`. Produces `SSLContext` and `AtiConnection` for MCP/A2A transport integration. Use when the application owns the TLS handshake (e.g. MCP SDK) and needs explicit `verifyServer()` after connect. Not an Agent — it is the client agent's SDK entry point.
_Avoid_: verified client (alone), mTLS client (implementation detail)

**AgentConnection**:
SDK connection handle returned by `AtiClient.connect()` — represents an established **Connection** to a server agent's `agentUrl`. Server Verification completes during connect; the handle exposes `HttpApiClient` for HTTP-API requests. Not an Agent.
_Avoid_: connection (alone — ambiguous with domain Connection concept or TLS session)

**AtiConnection**:
SDK connection handle returned by `AtiVerifiedClient.connect()` — represents a **Connection** in progress to a server agent. Holds pre-verification results (Badge/DANE expectations); the caller runs TLS via an external transport (MCP/A2A), then calls `verifyServer()` for **Post-verification**, returning a **Connection Verification Result**. Not an Agent.
_Avoid_: ATI connection (alone), verified connection (too vague)

**ConnectOptions**:
SDK configuration object passed to `AtiClient.connect()` when a client agent initiates a **Connection**. Carries the runtime **Verification Policy**, optional **identityHost** (Identity Hostname for Badge/identity DANE lookups) and **accessHost** (Access Hostname for server-cert `_443._tcp` DANE lookups), optional mTLS Identity Certificate material, TLSA lookup port (default 443), custom `TransparencyClient`, and HTTP auth headers. After Discovery, the SDK should populate both `identityHost` and `accessHost` from `AgentDetail`. Direct connect without Discovery requires explicit `identityHost` (and ideally `accessHost`) under the Dual Hostname Model. Default policy: `BADGE_REQUIRED`.
_Avoid_: connect config (too vague), connection options (prefer ConnectOptions — matches the SDK class name)

**Server Verification**:
Client-side verification of a target server agent during Connection, governed by Verification Policy. Runs Pre-verification (Badge on Identity Hostname, DANE TLSA on Identity Hostname for identity cert and on Access Hostname for server cert) and Post-verification (compare captured Server Certificate fingerprint). Symmetric counterpart to Client Verification.
_Avoid_: server-side verification (ambiguous — that is Client Verification), outbound verification (too vague)

**Verification Result**:
The outcome of Server Verification or Client Verification that determines whether a connection proceeds. Maps Registration Status from the TL Badge entry: `ACTIVE` → pass; `WARNING` / `DEPRECATED` → pass with warning; `REVOKED` / `EXPIRED` → reject. Lookup failures (missing Badge, DNS/TL errors) and fingerprint/name mismatches also produce a failed result. Use **Verification Result** for the domain conclusion — not to be confused with the homonymous SDK classes below.
_Avoid_: verification status (prefer Verification Result for the connection-time conclusion), trust result

**VerificationStatus**:
SDK enum (`com.aliyun.ati.sdk.transparency.verification.VerificationStatus`) implementing **Verification Result** for Badge/TL lookups. Key values:

- `VERIFIED` — ACTIVE registration, fingerprints match.
- `DEPRECATED_OK` — WARNING or DEPRECATED registration; connection allowed with warning.
- `REGISTRATION_INVALID` — REVOKED or EXPIRED registration.
- `FINGERPRINT_MISMATCH` — presented certificate fingerprint ≠ TL Badge entry.
- `ATI_NAME_MISMATCH` — Identity Certificate URI SAN ≠ Badge Entry `agentName`.
- `HOSTNAME_MISMATCH` — certificate CN ≠ Badge Entry `agentHost` (client verification path).
- `NOT_ATI_AGENT` — no `_ati-badge` TXT record found.
- `LOOKUP_FAILED` — DNS or TL fetch error.
- `SEAL_VERIFICATION_FAILED` — Seal signature or Merkle proof invalid.
_Avoid_: status code (alone — specify VerificationStatus when referring to the enum)

**Connection Verification Result**:
SDK record (`com.aliyun.ati.sdk.agent.verification.VerificationResult`) returned by `AtiConnection.verifyServer()` after post-verification. Combines DANE and Badge check outcomes per **Verification Policy** — distinct from transparency's `VerificationStatus` enum and from the domain **Verification Result** concept. Status values: `SUCCESS`, `MISMATCH`, `NOT_FOUND`, `ERROR`; types: `DANE`, `BADGE`, `PKI_ONLY`.
_Avoid_: VerificationResult (alone — specify Connection Verification Result in discussion, or use the fully qualified class name in code references)

**mTLS (Mutual TLS)**:
A TLS connection where both parties may present certificates — the server agent presents its Server Certificate, the client agent may present its Identity Certificate. Client-side connections typically use mTLS; server-side acceptance of client Identity Certificates follows **Verification Policy** and uses the **IDCA Chain** as trust material when policy is not None. Pre/Post-verification (Badge/DANE) runs on top of the TLS layer.
_Avoid_: two-way TLS (prefer mTLS), client-auth (implementation detail, not the domain concept)

**Server Certificate**:
The TLS certificate a server agent uses to serve HTTPS — proves the server's identity to connecting clients. Not issued by CNNIC or the RA — the agent operator provides it (bring-your-own certificate) or obtains it via ACME during registration. Used only for the transport layer; Identity Certificate handles mTLS agent identity.
_Avoid_: Service cert (prefer Server Certificate), TLS cert (alone — ambiguous with client-side TLS material)

**Identity Certificate**:
A CNNIC-issued, privately signed certificate that proves an agent's identity in mTLS. CNNIC issues one to every registered agent from the **IDCA Intermediate**, regardless of role. Used when an agent acts as client agent (presented on outbound connections). Server-side validation uses the **IDCA Chain** when Verification Policy is not None; when policy is None, client identity certificate verification is not performed. Carries the agent's ATI Name in the URI SAN (`ati://v{version}.{agentHost}`).
_Avoid_: Client cert (alone — ambiguous with any mTLS client certificate), mTLS cert, ATI-issued (identity certs are CNNIC-issued)

### Trust & Verification

**Badge**:
A registration credential issued by the RA for an agent, stored in the Transparency Log and discoverable via the DNS TXT record `_ati-badge.{agentHost}`. Badge verification confirms an agent is legitimately registered and binds certificate fingerprints to the registry record. Badge TXT lookup does not require DNSSEC.

The `_ati-badge` TXT record format: `v={format}; version={agentVersion}; url={tlUrl}` — where `v` is the **Badge Format Version** (currently `ati-badge1` only; legacy `ra-badge*` formats are rejected by the SDK), `version` is optional (the agent's SemVer, used during version rotation), and `url` points to the agent's entry in the TL. During version rotation, multiple TXT records may coexist under the same host.
_Avoid_: Token, credential (alone — too generic)

**Badge Entry**:
The full registration record stored in the TL for an agent, retrieved via the URL from a Badge TXT record. Uses schema version `ATI-TL-V1`, containing Registration Status (top-level `status`), ATI Name (`payload.agentName`), `payload.agentHost`, `payload.agentId`, `payload.version` (maps to `agentVersion` in RA/Discovery), certificate fingerprints (`serverCertFingerprint`, `identityCertFingerprint`), and an optional `evidenceRef`. Distinct from the DNS Badge TXT record, which only holds a pointer URL to this entry.
_Avoid_: TL record (too vague), badge payload (prefer Badge Entry)

**Evidence Ref**:
Metadata in a Badge Entry referencing the RA's original registration submission evidence (schema `ATI-EVIDENCE-V1`). Contains `evidenceId`, `submitterId` (RA, e.g. `aliyun`), `evidenceType`, `evidenceUri`, and `evidenceHash`. Used for audit traceability — Connection verification does not separately fetch or validate the evidence bytes, but `evidenceRef` is included in the Seal's JCS-signed content alongside `status`, `schemaVersion`, and `payload`.
_Avoid_: evidence (alone — too generic), submission record (prefer Evidence Ref when referring to TL metadata)

**Seal**:
The cryptographic signature on a Badge Entry in the Transparency Log. Verified during Badge pre-verification using the `publicKey` embedded in the Seal object (SHA-256withECDSA over RFC 8785 JCS-canonicalized content: `status`, `schemaVersion`, `payload`, `evidenceRef`). Related to but distinct from TL Root Key — the current SDK verifies Seal signatures with the per-response embedded key, not by fetching `/root-keys`.
_Avoid_: Signature (alone — too generic)

**TL Root Key**:
A root public key published by CNNIC at the TL `/root-keys` endpoint (C2SP format, keyed by hex key ID). Trust anchor for verifying SCITT Receipt and Status Token signatures when SCITT Header support is added. Cached by `RootKeyManager` in the SDK. Not the same as IDCA — TL Root Key attests log artifacts; IDCA issues Identity Certificates. The current Badge Seal verification path uses the `publicKey` embedded in each Seal response rather than `/root-keys`.
_Avoid_: root key (alone — specify TL Root Key), TL CA (TL signs log artifacts; IDCA is the identity CA)

**Merkle Proof**:
Evidence that a Badge entry exists in the TL's append-only Merkle tree, preventing forgery or tampering. Validated alongside the Seal during Badge pre-verification. Proves a single entry's inclusion — distinct from Checkpoint, which captures the whole tree's state.
_Avoid_: Proof (alone), hash chain

**Checkpoint**:
A periodically published Merkle tree state snapshot from the Transparency Log (RFC 6962-style), signed by the TL operator. Used to verify log consistency and detect fork or rollback — a TL audit/monitoring capability, not a required step in agent-to-agent Connection verification. The SDK exposes `TransparencyClient.getCheckpoint()` for consumers who want to monitor log integrity. Distinct from Merkle Proof, which proves a single Badge Entry's inclusion during Badge pre-verification.
_Avoid_: snapshot (alone), log state (too vague)

**Transparency Log (TL)**:
The append-only public log where Badges are stored, operated exclusively by CNNIC (default: `ati-tl.cnnic.cn:8180`; legacy: `tl.atiagent.cn`). CNNIC also operates the identity CA (IDCA) that issues Identity Certificates — together, TL and IDCA form ATI's trust infrastructure. Verification fetches the Badge entry, validates the Seal signature and Merkle proof, and compares certificate fingerprints. Badge URLs and `TransparencyClient.baseUrl` must resolve to a **Trusted TL Domain**. SDK access: `TransparencyClient` (`ati-sdk-transparency`), defaulting to `TransparencyClient.CNNIC_BASE_URL`; injectable via `ConnectOptions.transparencyClient()` for custom TL endpoints in tests. Distinct from the RA (Alibaba Cloud ATI), which manages registration and Discovery.
_Avoid_: TL (alone — spell out on first use), audit log, Alibaba Cloud TL (TL is CNNIC-operated, not Alibaba Cloud)

**Trusted TL Domain**:
A CNNIC transparency log hostname allowed in Badge URL pointers and `TransparencyClient.baseUrl`. Prevents a tampered `_ati-badge` TXT record from redirecting verification to a malicious log. Default trusted domains: `ati-tl.cnnic.cn` (production) and `tl.atiagent.cn` (legacy). Enforced by `BadgeUrlValidator` (Badge TXT `url` field) and `TrustedDomainRegistry` (`TransparencyClient` construction). Legacy Alibaba Cloud TL hostnames (e.g. `transparency.ati.aliyun.com`) are not trusted. Custom domains may be added via `BadgeUrlValidator` builder or the `ati.transparency.trusted.domains` system property for testing.
_Avoid_: trusted domain (alone — specify Trusted TL Domain), TL URL (too vague)

**Verification Policy**:
The trust verification level applied when establishing an agent-to-agent connection. Aligned with ATI Console levels L0–L3. Policies are progressive — each level includes all checks from the previous level (except None).

- **None** (`NONE`) — L0 无认证: server-only; skip inbound client verification (no client certificate requested); development and testing only. Client agents must always validate the server certificate and cannot use this policy.
- **Basic** (`BASIC`) — L1 基础认证: standard TLS PKI (system CA or IDCA on servers).
- **Enhanced** (`ENHANCED`) — L2 增强认证: Basic + Badge verification via the Transparency Log. Recommended production default.
- **Advanced** (`ADVANCED`) — L3 高级认证: Enhanced + DANE TLSA verification. Requires DNSSEC infrastructure.

On server agents, Verification Policy drives both TLS `client-auth` and whether Client Verification runs against the **IDCA Chain**:

- **None** — no client certificate requested; IDCA Chain unused.
- **Basic** — client certificate optional (`want`); production IDCA Chain is the default trust material.
- **Enhanced** / **Advanced** — client certificate required (`need`); production IDCA Chain is the default trust material.

A Server Agent may override the production IDCA Chain with a **Test IDCA Chain** or other non-production chain. The SDK ships the production IDCA Chain; supplying a chain path is optional.
_Avoid_: Security level (alone), trust mode (prefer Verification Policy)

**Pre-verification**:
The phase before the TLS handshake that asynchronously gathers verification expectations — Badge fingerprints from `_ati-badge` on the **Identity Hostname**, DANE TLSA from the **Access Hostname** (server cert) and/or **Identity Hostname** (identity cert), and TL Badge Entry data. Does not require the server's certificate yet. In the SDK, collected into `PreVerificationResult` by `AtiVerifiedClient.connect()` and held on `AtiConnection` for use during post-verification.
_Avoid_: Pre-check (too vague), upfront validation

**Post-verification**:
The phase after the TLS handshake that synchronously compares the captured server certificate against the expectations collected during **Pre-verification**. Fails the connection if fingerprints do not match. With `AtiClient`, post-verification runs automatically inside `connect()`. With `AtiVerifiedClient`, the caller invokes `AtiConnection.verifyServer()` after the external transport completes TLS — returns a **Connection Verification Result**.
_Avoid_: Post-check (too vague), cert validation (ambiguous with PKI)

**Certificate Fingerprint**:
The SHA-256 hash of a certificate, formatted as `SHA256:{64-char hex}` when computed by the SDK (`CertificateUtils.computeSha256Fingerprint`). TL Badge entries may use `SHA-256:{hex}` instead — both prefixes are equivalent; `CertificateUtils.fingerprintMatches()` normalizes prefix and case before comparison.

- **Server Cert Fingerprint** — fingerprint of the Server Certificate; compared during client-side post-verification of a server agent.
- **Identity Cert Fingerprint** — fingerprint of the Identity Certificate; compared during server-side verification of a client agent.
_Avoid_: cert hash (prefer Certificate Fingerprint), thumbprint (ambiguous with X.509 thumbprint format)

**IDCA (Identity CA)**:
The private two-tier certificate authority owned by CNNIC that issues Identity Certificates: an **IDCA Root** (operated by **UniTrust** under CNNIC commission) plus an **IDCA Intermediate** (CNNIC). Distinct from public CAs used for Server Certificates. The production **IDCA Chain** is the default trust material for **Client Verification** when Verification Policy is not None. A Server Agent may override it with a **Test IDCA Chain**. CNNIC embeds **CRL Distribution Points** on the Identity Certificate chain so relying parties can perform **Certificate Revocation** checks. When Verification Policy is None, Identity Certificate verification is skipped.
_Avoid_: CA (alone — ambiguous with public CA or Server Certificate issuer), ATI CA (prefer IDCA)

**IDCA Root**:
The production private root CA certificate that anchors the **IDCA Chain**. CNNIC commissions **UniTrust** to operate this root; it is not a CNNIC-named root certificate.
_Avoid_: 私签根证书, private root (alone), root CA (alone), CNNIC root (the Root is UniTrust-operated)

**IDCA Intermediate**:
The production private issuing CA certificate that signs Identity Certificates, itself signed by the **IDCA Root**. Operated by CNNIC.
_Avoid_: 私签二级证书, issuing CA (alone), intermediate CA (alone — prefer IDCA Intermediate)

**UniTrust**:
The organization CNNIC commissioned to operate the **IDCA Root**. Distinct from CNNIC, which issues Identity Certificates from the **IDCA Intermediate**.
_Avoid_: SHECA (CRL/OCSP host, not the Root operator), CNNIC (principal that owns IDCA, not the Root operator)

**IDCA Chain**:
Exactly two certificates: one production **IDCA Root** and one production **IDCA Intermediate**. A Server Agent loads **both** as trust material for **Client Verification** — not the Root alone — so a Client Agent may present only the leaf Identity Certificate. The SDK ships this pair as the default **server-side** trust material only; it is not attached to a Client Agent's outbound Identity Certificate. A Server Agent may replace it entirely with another two-certificate chain (a **Test IDCA Chain** or a rotated production pair) — override never merges with the shipped chain. Production **IDCA Intermediate** rotation is a hard cutover via that override; the shipped pair is updated in a later SDK release. Same process never trusts two production pairs at once. Distinct from the leaf Identity Certificate presented during mTLS.
_Avoid_: 私签证书链, trust PEM (alone), IDCA trust certificate (prefer IDCA Chain)

**Test IDCA Chain**:
A non-production IDCA Chain used only for tests and local demos. Distinct from the production **IDCA Chain**; must not be used as the Server Agent's production trust material.
_Avoid_: idca-chain (alone), ANS chain, test CA (prefer Test IDCA Chain)

**CRL Distribution Point (CDP)**:
An X.509 certificate extension (RFC 5280) embedding the HTTP URI where the issuing CA publishes its **Certificate Revocation List**. For Identity Certificates, CNNIC provides CDP on the certificate chain; the SDK reads CDP from the client Identity Certificate first, then from the issuing CA if absent. No operator-configured CRL URL — CDP is the sole production source.
_Avoid_: CRL URL (alone — prefer CDP when referring to the cert extension), revocation endpoint (too vague)

**Certificate Revocation**:
PKIX-layer revocation of an Identity Certificate — the certificate's serial number appears on the CA's CRL fetched via **CDP**. Checked during mTLS chain validation when IDCA is configured and the client presents an Identity Certificate. Distinct from **Registration Revocation**, which is enforced via TL Badge **Registration Status**. Both checks are complementary; either failure rejects the connection.
_Avoid_: cert revocation (alone — specify Certificate Revocation vs Registration Revocation), CRL check (implementation detail — prefer Certificate Revocation)

**Registration Revocation**:
Application-layer revocation of an agent's registration — TL Badge **Registration Status** is `REVOKED` or `EXPIRED`. Enforced during **Client Verification** (Badge lookup) for `ENHANCED`/`ADVANCED` server policies. Distinct from **Certificate Revocation** (CRL at the TLS layer). An agent may be revoked in the TL before the CRL reflects it, or vice versa; both paths must be checked when enabled.
_Avoid_: revocation (alone — ambiguous), CRL revocation (CRL is Certificate Revocation, not Registration Revocation)

**Client Verification**:
Server-side verification of an incoming client agent, governed by **Verification Policy**. When policy is not None, the production **IDCA Chain** is the default trust material (overridable by a **Test IDCA Chain**). Comprises two complementary layers: (1) TLS — Identity Certificate chain validation and **Certificate Revocation** via CDP/CRL; (2) application — Badge/DANE checks per Verification Policy, including **Registration Revocation** via TL **Registration Status**. Extracts the caller's ATI Name from the certificate URI SAN, then verifies via `_ati-badge` TXT + TL (Badge) and optionally `_ati-identity._tls` TLSA (DANE). When policy is None, client identity certificate verification is not performed. Does not rely on SCITT headers.
_Avoid_: client auth (too vague), inbound verification (prefer Client Verification)

**ClientRequestVerifier**:
SDK interface (`DefaultClientRequestVerifier`) implementing **Client Verification** on the server agent side. Takes the caller's Identity Certificate and `agentHost`, returns `ClientVerificationResult` with a `VerificationStatus`. Uses the **IDCA Chain** and **Verification Policy**. Symmetric counterpart to `AtiClient` / `AtiVerifiedClient` on the client agent side. Use **Client Verification** for the domain concept; `ClientRequestVerifier` when referencing server-side SDK code.
_Avoid_: client verifier (alone), inbound verifier (too vague)

**SCITT Header**:
HTTP headers carrying Transparency Log artifacts (Receipt, Status Token) for auditable attestation. Planned capability — **not supported in the current SDK version**; may be added in a future release. When supported, a client agent would attach its own SCITT artifacts to outgoing requests. Server-side client verification in ATI does not rely on SCITT headers — it uses Identity Certificate + Badge + DANE instead.
_Avoid_: Transparency header (prefer SCITT Header), SCITT (alone — spell out on first use)

**Receipt**:
A SCITT transparency receipt proving an agent's TL registration entry exists and has not been tampered with — the HTTP-transportable counterpart to Merkle Proof evidence. When SCITT Header support is added, a client agent may attach its Receipt to outbound requests for auditable attestation.
_Avoid_: SCITT receipt (prefer Receipt when context is SCITT), proof token

**Status Token**:
A SCITT token carrying an agent's Registration Status from the Transparency Log. Paired with Receipt in SCITT Header artifacts. Planned capability — not supported in the current SDK version.
_Avoid_: status header, badge token

### Identity

**Identity Hostname**:
The FQDN that anchors an agent's ATI registration, private Identity Certificate, and identity-related DNS records — e.g. `abc123.bailian.aliyun.com`. On shared platforms, must be a **first-level subdomain** of the agent's **Access Hostname** (e.g. `{label}.bailian.aliyun.com` under `bailian.aliyun.com`). In single-hostname deployment, may **equal** the Access Hostname (e.g. both `agent.example.com`). Pure DNS metadata namespace: no A/AAAA required, no TLS handshake. Discovery queries, `_ati` TXT, `_ati-badge` TXT, and `_ati-identity._tls` TLSA are published here. Synonymous with **agentHost** in RA/TL field names and ATI Name URIs.
_Avoid_: identity host (lowercase — prefer Identity Hostname), agent domain (too vague)

**Access Hostname**:
The FQDN where an agent's traffic lands — TLS handshake, public Server Certificate validation, and A/AAAA resolution — e.g. `bailian.aliyun.com` on a shared platform. Multiple agents may share one Access Hostname; each agent's **Identity Hostname** is a first-level subdomain (e.g. `abc123.bailian.aliyun.com`). Endpoint `agentUrl` values (`u=` in Discovery TXT) use this host; `_443._tcp` TLSA for Server Certificate DANE is published here. In **single-hostname mode**, equals `agentHost`.
_Avoid_: access host (lowercase — prefer Access Hostname), platform domain (too vague), agentHost (agentHost is the Identity Hostname)

**Dual Hostname Model**:
Conceptual separation of **Identity Hostname** (who the agent is — Discovery, Badge, identity DNS) from **Access Hostname** (where TLS lands — transport DANE). Exposed in **ConnectOptions** as `identityHost` and `accessHost`.

- **Shared platform (primary case)** — multiple agents share one Access Hostname; RA requires each agent's Identity Hostname to be a **first-level subdomain** of the Access Hostname (e.g. `abc123.bailian.aliyun.com` under `bailian.aliyun.com`); `u=` points to the Access Hostname.
- **Single-hostname deployment** — one agent独占 a domain; Identity Hostname **equals** Access Hostname (e.g. both `agent.example.com`); RA requires `agentHost` to equal the `u=` host.

When both hostnames are equal, Badge and transport DANE lookups target the same FQDN. The SDK does not require distinct hostnames.
_Avoid_: two-domain model (prefer Dual Hostname Model), split domain (too vague)

**RA Registration Constraints (`agentHost` vs `u=`)**:
- **Single-hostname deployment** — RA requires **`agentHost` to equal the host component of each endpoint `u=` URL** (e.g. both `agent.example.com`).
- **Shared platform** — RA requires **`agentHost` to be a first-level subdomain of the `u=` host** (Access Hostname) — e.g. `abc123.bailian.aliyun.com` under `bailian.aliyun.com`, with `u=` on `bailian.aliyun.com`.
_Avoid_: URL host mismatch (prefer stating the mode-specific constraint explicitly)

**agentHost**:
The RA/TL field name and SDK identifier for an agent's **Identity Hostname** — e.g. `abc123.bailian.aliyun.com`. Used as the primary key for Discovery queries and embedded in ATI Name (`ati://v{version}.{agentHost}`). When Identity Hostname equals Access Hostname (single-hostname deployment), both roles collapse to the same FQDN — the degenerate case of the dual-hostname model.
_Avoid_: hostname (alone — ambiguous with Access Hostname or machine hostname), domain (too vague)

**agentId**:
The unique registration ID assigned by the RA to an agent (UUID), stored in TL Badge entries. Identifies a specific registration record within RA/TL systems. Obtained during Connection Badge pre-verification (from `_ati-badge` URL), not from DNS Discovery. Distinct from agentHost (a host may have multiple agentIds during version rotation) and from ATI Name (the URI embedded in the Identity Certificate).
_Avoid_: agent UUID (prefer agentId — matches the RA field name), ATI Name (different identifier)

**ATI Name**:
The canonical URI identifier for an agent, including version: `ati://v{version}.{agentHost}` (e.g. `ati://v1.0.0.agent.example.com`). Embedded in the Identity Certificate's URI SAN. In TL Badge Entry payload, the same value appears under the field name `agentName` — use **ATI Name** in discussion, `agentName` when referencing TL JSON.
_Avoid_: agent URI (prefer ATI Name), ANS name (out of scope — ANS uses `ans://`), agentName (alone — prefer ATI Name unless citing TL schema field names)

**agentVersion**:
The SemVer version of an agent as recorded in the RA registration — e.g. `1.0.0`. Also embedded in the ATI Name and optionally in Badge DNS TXT records during version rotation.
_Avoid_: version (alone — ambiguous with version constraint or ATI Name prefix)

**Version Constraint**:
A SemVer matching expression passed to Discovery — e.g. `1.0.0` (exact), `^1.0.0` (compatible), `~1.2.0` (approximate). Resolved client-side against the `av` field in `_ati` Discovery TXT records on the Identity Hostname. When multiple records satisfy the constraint, Discovery picks the **latest** matching `av`. When omitted, Discovery defaults to the **latest** `av` among all TXT records. The `av` prefix `v` (e.g. `v1.0.0`) is normalized before comparison.
_Avoid_: version filter, semver query

**Version Rotation**:
The coexistence of multiple agentVersion values under the same agentHost during upgrades. DNS may hold multiple Discovery TXT records (each with a distinct `av`) and multiple Badge TXT records (each tagged with `version=`). Discovery filters by Version Constraint and selects the latest matching `av`; Badge pre-verification accepts any matching fingerprint.
_Avoid_: version upgrade (too vague), rolling update

**DANE**:
DNS-based Authentication of Named Entities — verification that a presented certificate or public key matches a TLSA record published for the agent's domain. TLSA records are validated with DNSSEC during DANE verification.
_Avoid_: DNS verification (alone — too broad), certificate pinning (different mechanism)

**DNSSEC**:
DNS Security Extensions — cryptographic signing of DNS responses (DNSKEY/RRSIG) to prevent tampering. Required only for DANE TLSA verification, not for Badge TXT lookup. Badge pre-verification reads `_ati-badge` TXT records and validates entries via the Transparency Log (Seal + Merkle Proof) without requiring DNSSEC.
_Avoid_: DNS security (too vague), DNS signing (implementation detail)

**TLSA Record**:
A DNS record binding a domain to an expected certificate or public key fingerprint. Requires DNSSEC when used for DANE verification (unlike Badge TXT lookup).

ATI publishes TLSA at two distinct prefixes on two hostnames — must not be mixed:
- **Server Certificate** — `_443._tcp.{accessHost}` on the **Access Hostname**; used in client-side DANE verification during Server Verification.
- **Identity Certificate** — `_ati-identity._tls.{agentHost}` on the **Identity Hostname**; used in server-side Client Verification.

ATI's default TLSA convention is **`3 1 1`** (RFC 6698): Usage 3 (Domain-issued certificate, coexists with PKI), Selector 1 (SPKI/public key), Matching Type 1 (SHA-256 hash). The SDK's `TlsaUtils` can handle other selector/matching-type combinations if published, but registration docs and examples assume `3 1 1`.
_Avoid_: DNS record (alone), TLS record
