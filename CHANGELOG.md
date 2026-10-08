# Changelog

All notable changes to the ATI Java SDK are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [4.0.0] - 2026-10-08

### Breaking Changes

- **Seal Certificate required for Badge pre-verification** (ADR-0011): Badge pre-verification now path-validates the **Seal Certificate** (`seal.certificate`) against the SDK-shipped **Seal CA Chain** (Seal CA Root + Intermediate) and binds the leaf Subject to `O=中国互联网络信息中心` + `OU=ATI`. The legacy self-asserted `seal.publicKey`-only path is removed: a Seal without `seal.certificate` now fails closed with `SEAL_VERIFICATION_FAILED`. `SealVerifier.verify(log)` anchors on the shipped chain (it previously trusted the Seal's own `publicKey`), so any chain failure — path, expiry, Subject binding, signature, or anchor load — surfaces as `SEAL_VERIFICATION_FAILED` and fails Badge pre-verification. Seal verification still runs only at Badge policies (`ENHANCED`/`ADVANCED`); no separate toggle is added.

### Added

- **`ati.sdk.transparency.seal.trust-certificate` override**: operators can replace the shipped Seal CA Chain with a two-certificate (Root + Intermediate) PEM without an SDK upgrade. Blank/unset uses the shipped chain; a present-but-missing or malformed override fails closed at startup. The property flows Spring → a shared `SealTrustChain` bean → server `BadgeVerificationService` (Client Verification) and outbound `AtiVerifiedClient` / `DefaultAgentHttpClientFactory` (Connection pre-verification). `SealVerifier.verify(log, sealTrustChain)` accepts an injected chain directly.

### Changed

- **Seal Certificate validity as-of sealing time** (ADR-0012): Badge pre-verification now validates the Seal Certificate and its whole chain (`leaf → Intermediate → Root`) as-of the **Seal Validation Time** `min(payload.timestamp, now)` — the entry's own JCS-signed sealing time — instead of verification-time "now". A genuine long-lived or historical Badge Entry whose leaf has expired *since it was sealed* now verifies, while a signature sealed after the leaf's `notAfter` still fails closed with `SEAL_VERIFICATION_FAILED`. A future `payload.timestamp` is clamped to `now`; a missing, blank, or unparseable timestamp falls back to `now`. Applies to both `SealVerifier.verify(log)` and `verify(log, sealTrustChain)`; no new public API or `VerificationStatus`.

## [3.1.0] - 2026-09-14

### Added

- **Certificate Renewal** (ADR-0010): a Badge Entry on `ATI-TL-V1` may carry optional `previousServerCertFingerprint` and `previousIdentityCertFingerprint`. Badge verification matches **same-role OR** — a presented Server Certificate hits current ∪ Previous Server Cert Fingerprint; a presented Identity Certificate hits current ∪ Previous Identity Cert Fingerprint. The two previous fields are independently optional; the current fingerprint for that role remains required (previous cannot stand in for a missing current). Previous is one slot, not a history list; missing or blank means that role is not in a window. Hitting previous is the same Verification Result as hitting current (`VERIFIED` / `DEPRECATED_OK`); `REVOKED` / `EXPIRED` still fail. DANE is unchanged (`previous*` is not copied into TLSA). Un-upgraded SDKs ignore the new keys and still accept the current certificate.

## [3.0.0] - 2026-09-07

### Breaking Changes

- **Server `BASIC` requires an Identity Certificate** (ADR-0008): `ati.sdk.server.verification.policy=BASIC` now derives TLS `client-auth=need`, same as `ENHANCED`/`ADVANCED`. A Client Agent that does not present an Identity Certificate fails the handshake. Anonymous TLS is `NONE` only; `client-auth` cannot be overridden back to `want`. Application-layer Client Verification is still invoked by the application. Client-side `BASIC` still allows omitting an outbound Identity Certificate.
- **Seal signature algorithm** (ADR-0009): CNNIC production Seal is SHA-256withRSA only. `signatureAlgorithm` must be SHA-256withRSA (normalized); missing or any other value — including SHA-256withECDSA — fails Badge pre-verification.

### Changed

- **Default Transparency Log base URL moved to standard HTTPS (443)**: `TransparencyClient.CNNIC_BASE_URL` and the Spring `ati.sdk.transparency.base-url` default changed from `https://ati-tl.cnnic.cn:8180` to `https://ati-tl.cnnic.cn`, in sync with CNNIC serving the TL on standard HTTPS. The Trusted TL Domain check is host-only, so the previous `:8180` endpoint still works when set explicitly via `ati.sdk.transparency.base-url` or `.baseUrl(...)`.

### Fixed

- **Bundled IDCA Chain was staging, now production**: the SDK-shipped default server trust pair (`IdcaChain`) was the pre-release/staging chain (Root `UniTrust ATI RSA Root CA R1 TEST` + Intermediate `CNNIC ATI RSA CA 2026 TEST`, `*-staging.sheca.com` endpoints). It is replaced with the production pair — Root `CN=CNNIC ATI RSA Root CA R1` + Intermediate `CN=CNNIC ATI RSA CA 2026`, `*.global.sheca.com` endpoints. The production Root is CNNIC-named and CNNIC-owned; UniTrust/SHECA operates its CRL/OCSP/CA-Issuers infrastructure. ADR-0002 and ADR-0005 and the glossary are corrected accordingly. Server agents relying on the bundled default now trust production identity; agents that need the test pair must set `ati.sdk.server.idca.trust-certificate`.

## [2.1.0] - 2026-08-17

### Added

- **Bundled production IDCA Chain** (`IdcaChain`): the SDK now ships the production Root + Intermediate certificate pair as the default server-side trust for client identity verification (ADR-0005). Server agents no longer need to provide a PEM path at `BASIC`+ policies; the `trust-certificate` property can still replace the bundled chain without an SDK upgrade.

### Changed

- **Hostname narrative**: README and glossary use **Independent Domain Mode** and **Shared Domain Mode**. The two host concepts are **Identity Hostname** (`identityHost`) and **Access Hostname** (`accessHost`). Discovery `getAgentHost()` is identityHost. TL JSON `payload.agentHost` is Access Hostname; Identity Hostname is `payload.agentSubHost` when non-blank (ADR-0007). Dual Hostname Model is avoided.

### Fixed

- **Badge Identity Hostname**: derive identity as `payload.agentSubHost` when non-blank, otherwise `payload.agentHost`. Shared Domain Mode Badge hostname matching no longer compares URI SAN / lookup host to Access Hostname (`payload.agentHost`).
- **Seal JCS evidenceRef**: keep the raw TL `evidenceRef` map for signature canonicalization. Typed `EvidenceRef` dropped unknown keys (e.g. evidence-object signature fields), so production Seal verification failed.
- **IDCA Chain verification error handling**: preserve JCE/FIPS provider errors when verifying the bundled chain. Missing algorithms and other provider errors are rethrown with the original cause instead of being misreported as a Root/Intermediate pairing failure; signature mismatch remains a chain-structure failure.
- **Discovery TXT parse**: parse `_ati` records as unordered `ati1` KV (`v`, `av`, `p`, `u`, optional `m`). Skip unimplemented `ati{N}` family versions, non-SemVer `av`, and `p=` outside `mcp` / `a2a` / `http-api`; `discover` still succeeds if any valid records remain.
- **Badge TXT parse**: parse `_ati-badge` as `ati-badge1` with required `av=` / `u=` (obsolete `version=` / `url=` are ignored). Skip other `ati-badge{N}` and out-of-family values.
- **Badge verification path fetch**: do not drop a Badge because the TXT `u=` host is outside Trusted TL Domain. Extract the path from `u=` and request `TransparencyClient.baseUrl` + that path; path traversal is rejected on that fetch. Constructing `TransparencyClient` with an untrusted `baseUrl` host still fails.

## [2.0.0] - 2026-07-28

First open-source release of the ATI Java SDK.

### Breaking Changes

- **Discovery**: replace RA OpenAPI discovery with DNS TXT discovery via `_ati.{identityHost}` records; remove `AtiDiscoveryIntegrationTest` and related RA OpenAPI client paths.
- **VerificationPolicy**: rename policies to align with ATI Console trust levels. Migrate as follows:

  | Previous (internal) | 2.0.0        |
  |---------------------|--------------|
  | `PKI_ONLY`          | `BASIC`      |
  | `BADGE_REQUIRED`    | `ENHANCED`   |
  | `DANE_AND_BADGE`    | `ADVANCED`   |
  | —                   | `NONE` (new, server-side inbound auth only) |

  Legacy policy names such as `PKI_ONLY` are no longer accepted by `VerificationPolicy.fromString()`.
- **Dual-hostname connect model**: separate **Identity Hostname** (Badge/DANE/trust) from **Access Hostname** (transport `agentUrl` host). See ADR-0003.
- **Badge format**: drop `ra-badge1` support; Badge verification uses the CNNIC Transparency Log format only.
- **Transparency Log URLs**: remove legacy Aliyun TL URLs; CNNIC is the sole Transparency Log (ADR-0001).
- **Client agents**: `VerificationPolicy.NONE` is rejected for outbound connections; client agents must use `BASIC`, `ENHANCED`, or `ADVANCED`.

### Added

- **IDCA CRL revocation** (server-side): CDP extraction, CRL fetch/cache, PKIX validation, and Spring Boot mTLS integration for embedded Tomcat (ADR-0004).
- **Domain glossary** (`CONTEXT.md`) and architecture decision records (`docs/adr/0001`–`0004`).
- **Agent contributor docs** under `docs/agents/` (domain model, issue tracker, triage labels).
- Expanded unit and integration test coverage for dual-hostname verification, IDCA CRL, and Spring server mTLS.

### Changed

- **CNNIC Identity CA** documented as the sole identity certificate issuer (ADR-0002).
- **Default verification policy** for client connections remains badge-enabled (`ENHANCED`).
- README and module READMEs updated for DNS discovery, verification policies, and CRL behavior.

### Fixed

- IDCA CRL fail-closed behavior and cache handling in core and Spring integration.
- Restrict `NONE` verification policy to server-side configuration only.
- README accuracy for CRL, dual-hostname connect, and API examples.

[4.0.0]: #
[3.1.0]: #
[3.0.0]: #
[2.1.0]: #
[2.0.0]: #
