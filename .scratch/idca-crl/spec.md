# Spec: IDCA CRL Certificate Revocation (Server-Side)

**Status:** ready-for-implementation  
**ADR:** [docs/adr/0004-idca-crl-revocation.md](../../docs/adr/0004-idca-crl-revocation.md)  
**Research:** [research.md](./research.md)

## Goal

When a server agent validates a client **Identity Certificate** over mTLS, reject revoked certificates via **PKIX CRL** fetched from **CDP** on the certificate chain.

## Non-goals (this phase)

- OCSP
- Operator-configured CRL URL fallback
- Client-side CRL
- Replacing TL Badge **Registration Revocation**

## Requirements

### R1 — CDP discovery

- Read CDP from client Identity Certificate (leaf).
- If absent, read CDP from issuing CA certificate in the presented chain.
- If no CDP on chain: **skip CRL** (log at debug); do not fail.
- CDP extension present but malformed or without a usable HTTP(S) URI: treat as **CRL path active** and **fail-closed** (R3).

### R2 — CRL fetch and validate

- HTTP(S) fetch CRL from CDP URI.
- Verify CRL signature against issuing CA.
- Reject connection if client cert serial is on CRL.

### R3 — Fail-closed when CRL path active

- If CDP exists and CRL check is attempted: fetch failure, invalid signature, or unparsable CRL → **reject** mTLS.

### R4 — Policy scope

- Run CRL when `ati.sdk.server.idca.trust-certificate` is configured **and** client presents a certificate.
- Applies to server policies `BASIC`, `ENHANCED`, `ADVANCED`; not `NONE`.

### R5 — Dual-track with Badge

- Do not remove or bypass existing `DefaultClientRequestVerifier` Badge checks.
- Certificate Revocation (CRL) and Registration Revocation (Badge) are independent; either failure rejects.

### R6 — CRL cache

- Cache CRL per CDP URI.
- Refresh when `nextUpdate` is reached.
- Force refresh at least every **12 hours** even if `nextUpdate` is later.

### R7 — Testing

- Unit/integration tests use mock CDP/CRL fixtures only.
- No production configuration for CRL URLs.
- Unrelated test-file splits (checkstyle/refactor) are out of scope for CRL acceptance; CRL behavior is covered by `*Crl*` and dual-track tests below.

## Implementation sketch

```
AtiServerAutoConfiguration
  └─ custom SSL / TrustManager with PKIXRevocationChecker
       └─ CrlRevocationChecker (new)
            ├─ CdpExtractor (leaf → issuer)
            ├─ CrlFetcher (HTTP, cached)
            └─ CrlValidator (signature + serial lookup)
```

`DefaultClientRequestVerifier` unchanged for Badge/DANE; CRL stays in TLS layer.

**Spring Boot note:** TLS-layer CRL is wired via embedded **Tomcat** connector customization. Other embedded containers log a warning and skip CRL until supported.

## Open dependency

CNNIC must publish **CDP** on production Identity Certificates or Issuing CA. Demo certs in-repo currently lack CDP.

## Acceptance criteria

1. Mock cert with CDP → revoked serial on CRL → mTLS rejected.
2. Mock cert with CDP → serial not on CRL → mTLS proceeds (Badge rules still apply). Covered by `AtiIdcaCrlBadgeDualTrackIntegrationTest`.
3. Mock cert without CDP → mTLS proceeds without CRL (no fail-closed).
4. CDP present, CRL URL unreachable → mTLS rejected.
5. CRL cache respects `nextUpdate` and 12h max staleness.
