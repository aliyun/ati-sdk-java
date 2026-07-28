---
status: accepted
---

# IDCA Certificate Revocation via CDP/CRL

Server-side mTLS validation of client **Identity Certificates** adds **Certificate Revocation** at the TLS/PKIX layer, complementary to existing **Registration Revocation** via TL Badge (`REVOKED`/`EXPIRED`).

CNNIC embeds **CRL Distribution Points (CDP)** on the Identity Certificate chain. The SDK reads CDP only — no operator-configured CRL URL fallback. CDP resolution follows PKIX convention: client leaf first, then issuing CA. If no CDP is present, CRL checking is skipped (production dependency on CNNIC publishing CDP). Tests may use mock CDP/CRL fixtures.

When CDP exists and CRL checking runs: fetch or validation failure is **fail-closed** (reject the connection). CRL applies whenever IDCA trust is configured and the client presents an Identity Certificate — all server policies except `NONE`. OCSP is out of scope for this phase. CRL is cached and refreshed per `nextUpdate`, with a maximum refresh interval of 12 hours.

## Considered options

- **Configurable CRL URL fallback** — rejected; CNNIC owns CDP publication; avoids operator drift from CA policy.
- **CRL replaces Badge revocation** — rejected; TL Badge provides auditable registration lifecycle; dual-track is safer.
- **OCSP in the same phase** — rejected; demo certificates lack AIA; CRL-only reduces scope.
- **Fail-open on CRL fetch failure** — rejected; undermines PKIX revocation when CDP is present.

## Consequences

- New CRL fetching/caching component wired into Spring server SSL / PKIX path validation.
- `BASIC` server policy relies solely on CRL for Certificate Revocation; `ENHANCED`/`ADVANCED` also enforce Registration Revocation via Badge.
- Production CRL support blocked until CNNIC ships certificates with CDP (current demo certs lack CDP).
- ANS v2 NFR-P-03 (< 5 min CA-side CRL update) is a CNNIC SLA; SDK cache may lag up to 12h on the CRL path — Badge covers faster revocation for `ENHANCED`/`ADVANCED`.
