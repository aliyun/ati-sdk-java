# Changelog

All notable changes to the ATI Java SDK are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [2.1.0] - 2026-08-17

### Added

- **Bundled production IDCA Chain** (`IdcaChain`): the SDK now ships the production Root + Intermediate certificate pair as the default server-side trust for client identity verification (ADR-0005). Server agents no longer need to provide a PEM path at `BASIC`+ policies; the `trust-certificate` property can still replace the bundled chain without an SDK upgrade.

### Fixed

- **IDCA Chain verification error handling**: preserve JCE/FIPS provider errors when verifying the bundled chain. Missing algorithms and other provider errors are rethrown with the original cause instead of being misreported as a Root/Intermediate pairing failure; signature mismatch remains a chain-structure failure.

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
