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
A protocol-specific service surface published by an agent — e.g. MCP or A2A — identified by an `agentUrl`, a **Protocol**, and optional **Transport** list in the registry record.
_Avoid_: URL (alone), API (when the protocol is MCP or A2A)

**Agent Lifecycle Status**:
The registration state of an agent in the RA, following the state machine: `PENDING` → `PENDING_DNS` → `ACTIVE` → `DEPRECATED` → `REVOKED`.

- `PENDING` — registration in progress, verification not yet complete.
- `PENDING_DNS` — awaiting DNS record verification (TLSA, Badge TXT).
- `ACTIVE` — fully registered, discoverable, and safe for production connections.
- `DEPRECATED` — still connectable with a warning; callers should migrate to a newer version.
- `REVOKED` — registration revoked; connections must be rejected.

Returned as `status` on `AgentDetail` from Discovery. TL Badge Entry payload may also carry a snapshot as `payload.agentStatus` — semantically related, but Connection verification uses TL top-level **Registration Status**, not RA lifecycle status or `payload.agentStatus`.
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
The HTTP transport mode declared on an Endpoint — e.g. `STREAMABLE-HTTP` for MCP. Answers *how* to carry the Protocol over HTTP. Returned in `AgentEndpoint.transports` from Discovery. The client agent uses Transport to select an SDK transport implementation (e.g. `HttpClientStreamableHttpTransport` for MCP). Does not participate in Badge/DANE trust verification.
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
The connectable HTTPS URL of an Endpoint — e.g. `https://agent.example.com/mcp`. The target address for Connection after Discovery selects an Endpoint.
_Avoid_: URL (alone), endpoint URL (prefer agentUrl — matches the RA field name)

**metaDataUrl**:
An optional URL on an Endpoint pointing to the agent's capability metadata (e.g. an Agent Card or service descriptor). Not used for TLS connection — informational only. RA OpenAPI field name: `MetadataUrl`. The discovery module's `AgentEndpoint.metadataUrl` is the same field — use **metaDataUrl** in discussion, `getMetadataUrl()` when referencing discovery module Java code.
_Avoid_: metadata endpoint, description URL, metadataUrl (alone — prefer metaDataUrl unless citing discovery module field names)

**Agent Card**:
A self-published metadata document describing an agent's capabilities, skills, and interfaces — typically JSON, often used with the A2A protocol. Discovered via an Endpoint's `metaDataUrl`. Complements AgentDetail: AgentDetail answers who is registered and where to connect; Agent Card answers what the agent can do after connecting. Does not participate in Badge/DANE trust verification.
_Avoid_: agent metadata (too vague), capability descriptor (prefer Agent Card when referring to A2A-style documents)

**RA (Registration Authority)**:
The authoritative system that manages agent registration and lifecycle. In this SDK, Alibaba Cloud ATI service is the RA — providing ATI Console, Discovery OpenAPI, endpoint metadata, and `trustLevel`. Distinct from CNNIC, which operates the trust infrastructure (Transparency Log and Identity Certificate issuance). Badge verification links the two: DNS `_ati-badge` points to TL entries (CNNIC) that attest RA registration records.
_Avoid_: Registry (alone — too generic), Console (RA is the service; Console is just one interface to it)

**CNNIC**:
China Internet Network Information Center — the national authority that operates ATI's trust infrastructure. Responsibilities include the Transparency Log (Badge storage, Seal, and Merkle Proof) and Identity Certificate issuance via IDCA. Provides regulatory credibility for privately signed agent identity. Distinct from the RA (Alibaba Cloud ATI), which manages registration and Discovery.
_Avoid_: TL operator (alone — CNNIC also operates IDCA), CA provider (prefer CNNIC when referring to the institutional role)

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
Querying the RA's OpenAPI to resolve a registered agent's details (host, version, endpoints) by `agentHost` and optional version constraint. Returns `AgentDetail`. DNS lookups for `_ati-badge` TXT and TLSA records happen during Connection pre-verification, not during Discovery.
_Avoid_: DNS lookup (alone — discovery goes through OpenAPI, not direct DNS resolution of agent records), DNS-based discovery (inaccurate for this SDK — use registry-based or OpenAPI-based discovery)

**AgentDetail**:
The result returned by Discovery — a snapshot of an agent's RA registration record, including `agentId`, `agentHost`, `agentVersion`, `status`, `trustLevel`, and `endpoints`. Used by a client agent to select an Endpoint and initiate a Connection. The discovery module exposes this as `com.aliyun.ati.sdk.discovery.AgentDetail`. The generated model `AgentDetails` in `ati-sdk-core` represents the same RA snapshot — prefer `AgentDetail` in new code; use `AgentDetails` only when working with `AtiClient` internals.
_Avoid_: agent record (too vague), discovery response (prefer AgentDetail), AgentDetails (alone — prefer AgentDetail unless citing the core generated class)

**trustLevel**:
A trust rating assigned by the RA to an agent (e.g. `HIGH`, `MEDIUM`), returned in AgentDetail. Informational — it does not automatically change the client agent's Verification Policy choice.
_Avoid_: trust score, security level (prefer trustLevel — matches the RA field name)

**Connection**:
Establishing a verified TLS link to an agent's endpoint URL — running pre-verification (Badge/DANE), TLS handshake, and post-verification (fingerprint comparison). Does not require prior Discovery; can connect directly to a known `agentUrl`. Encompasses Server Verification when initiated by a client agent.
_Avoid_: Session (alone — ambiguous with HTTP session), link (too vague)

**AtiClient**:
SDK client class for the simplified integration path — `connect(agentUrl, ConnectOptions)` returns an `AgentConnection` for HTTP-API request/response. Encapsulates Badge/DANE pre/post-verification internally. Recommended for quick HTTP-API integrations. Not an Agent — it is the client agent's SDK entry point.
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
SDK configuration object passed to `AtiClient.connect()` when a client agent initiates a **Connection**. Carries the runtime **Verification Policy**, optional mTLS Identity Certificate material, TLSA lookup port (default 443), custom `TransparencyClient`, and HTTP auth headers. Not an ATI protocol field — the SDK API wrapper for connection-time settings. Default policy: `BADGE_REQUIRED`.
_Avoid_: connect config (too vague), connection options (prefer ConnectOptions — matches the SDK class name)

**Server Verification**:
Client-side verification of a target server agent during Connection, governed by Verification Policy. Runs Pre-verification (Badge/DANE expectations from DNS and TL) and Post-verification (compare captured Server Certificate fingerprint). Symmetric counterpart to Client Verification.
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
A TLS connection where both parties may present certificates — the server agent presents its Server Certificate, the client agent may present its Identity Certificate. Client-side connections typically use mTLS; server-side acceptance of client Identity Certificates depends on IDCA configuration. Pre/Post-verification (Badge/DANE) runs on top of the TLS layer.
_Avoid_: two-way TLS (prefer mTLS), client-auth (implementation detail, not the domain concept)

**Server Certificate**:
The TLS certificate a server agent uses to serve HTTPS — proves the server's identity to connecting clients. Not issued by CNNIC or the RA — the agent operator provides it (bring-your-own certificate) or obtains it via ACME during registration. Used only for the transport layer; Identity Certificate handles mTLS agent identity.
_Avoid_: Service cert (prefer Server Certificate), TLS cert (alone — ambiguous with client-side TLS material)

**Identity Certificate**:
A CNNIC-issued, privately signed certificate that proves an agent's identity in mTLS. CNNIC operates the identity CA and issues one to every registered agent, regardless of role. Used when an agent acts as client agent (presented on outbound connections). Server-side validation of a caller's Identity Certificate requires IDCA to be configured on the server agent; without IDCA, client identity certificate verification is not performed. Carries the agent's ATI Name in the URI SAN (`ati://v{version}.{agentHost}`).
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
The trust verification level applied when establishing an agent-to-agent connection. Policies are progressive — each level includes all checks from the previous level.

- **PKI Only** (`PKI_ONLY`) — 基础认证: standard TLS with system CA validation only.
- **Badge Required** (`BADGE_REQUIRED`) — 增强认证: PKI + Badge verification via the Transparency Log. Recommended production default.
- **DANE and Badge** (`DANE_AND_BADGE`) — 最高认证: PKI + Badge + DANE TLSA verification. Requires DNSSEC infrastructure.
_Avoid_: Security level (alone), trust mode (prefer Verification Policy)

**Pre-verification**:
The phase before the TLS handshake that asynchronously gathers verification expectations — DANE TLSA hashes and/or Badge fingerprints from DNS and the Transparency Log. Does not require the server's certificate yet. In the SDK, collected into `PreVerificationResult` (`com.aliyun.ati.sdk.agent.verification`) by `AtiVerifiedClient.connect()` and held on `AtiConnection` for use during post-verification.
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
The private certificate authority operated by CNNIC to issue Identity Certificates. Distinct from public CAs used for Server Certificates. Optional on server agents — configuring the IDCA trust anchor enables mTLS client Identity Certificate chain validation and **Client Verification**. Spring Boot: `ati.sdk.server.idca.trust-certificate` (path to CNNIC IDCA PEM). Programmatic: pass IDCA trust material to `ClientRequestVerifier` / `DefaultClientRequestVerifier`. When IDCA is not configured, caller Identity Certificate verification is skipped to reduce integration complexity.
_Avoid_: CA (alone — ambiguous with public CA or Server Certificate issuer), root CA, ATI CA (IDCA is CNNIC-operated)

**Client Verification**:
Server-side verification of an incoming client agent, governed jointly by **Verification Policy** and **IDCA** configuration. When IDCA is configured, the server agent validates the caller's Identity Certificate chain (IDCA) and applies Badge/DANE checks per Verification Policy — extracting the caller's ATI Name from the certificate URI SAN, then verifying via `_ati-badge` TXT + TL (Badge) and optionally `_ati-identity._tls` TLSA (DANE). When IDCA is not configured, client identity certificate verification is not performed. Does not rely on SCITT headers.
_Avoid_: client auth (too vague), inbound verification (prefer Client Verification)

**ClientRequestVerifier**:
SDK interface (`DefaultClientRequestVerifier`) implementing **Client Verification** on the server agent side. Takes the caller's Identity Certificate and `agentHost`, returns `ClientVerificationResult` with a `VerificationStatus`. Requires IDCA trust configuration and Verification Policy. Symmetric counterpart to `AtiClient` / `AtiVerifiedClient` on the client agent side. Use **Client Verification** for the domain concept; `ClientRequestVerifier` when referencing server-side SDK code.
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

**agentHost**:
The FQDN that uniquely identifies an agent in the RA — e.g. `agent.example.com`. Used as the primary key for Discovery queries.
_Avoid_: hostname (alone — ambiguous with machine hostname), domain (too vague)

**agentId**:
The unique registration ID assigned by the RA to an agent (UUID), returned in AgentDetail and stored in TL Badge entries. Identifies a specific registration record within RA/TL systems. Distinct from agentHost (a host may have multiple agentIds during version rotation) and from ATI Name (the URI embedded in the Identity Certificate).
_Avoid_: agent UUID (prefer agentId — matches the RA field name), ATI Name (different identifier)

**ATI Name**:
The canonical URI identifier for an agent, including version: `ati://v{version}.{agentHost}` (e.g. `ati://v1.0.0.agent.example.com`). Embedded in the Identity Certificate's URI SAN. In TL Badge Entry payload, the same value appears under the field name `agentName` — use **ATI Name** in discussion, `agentName` when referencing TL JSON.
_Avoid_: agent URI (prefer ATI Name), ANS name (out of scope — ANS uses `ans://`), agentName (alone — prefer ATI Name unless citing TL schema field names)

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
A DNS record binding a domain to an expected certificate or public key fingerprint. Requires DNSSEC when used for DANE verification (unlike Badge TXT lookup).

ATI publishes TLSA at two distinct prefixes — must not be mixed:
- **Server Certificate** — `_443._tcp.{agentHost}`; used in client-side DANE verification during Server Verification.
- **Identity Certificate** — `_ati-identity._tls.{agentHost}`; used in server-side Client Verification.

ATI's default TLSA convention is **`3 1 1`** (RFC 6698): Usage 3 (Domain-issued certificate, coexists with PKI), Selector 1 (SPKI/public key), Matching Type 1 (SHA-256 hash). The SDK's `TlsaUtils` can handle other selector/matching-type combinations if published, but registration docs and examples assume `3 1 1`.
_Avoid_: DNS record (alone), TLS record
