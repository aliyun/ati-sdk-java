# Changelog

All notable changes to the ATI Java SDK are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Breaking Changes

- **Server `BASIC` requires an Identity Certificate** (ADR-0008): `ati.sdk.server.verification.policy=BASIC` now derives TLS `client-auth=need`, same as `ENHANCED`/`ADVANCED`. A Client Agent that does not present an Identity Certificate fails the handshake. Anonymous TLS is `NONE` only; `client-auth` cannot be overridden back to `want`. Application-layer Client Verification is still invoked by the application. Client-side `BASIC` still allows omitting an outbound Identity Certificate.

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

[2.1.0]: #
[2.0.0]: #
