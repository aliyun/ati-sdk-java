---
status: accepted
---

# Seal Certificate validity is checked as-of the entry's sealing time, not "now"

The Transparency Log is append-only: a **Badge Entry** keeps the **Seal Certificate** it was sealed with and is never re-sealed. ADR 0011 enforced that certificate's validity at *verification time* — "an expired or not-yet-valid leaf fails closed." Because the leaf rotates ~yearly, any entry sealed more than ~1 year ago (a long-lived registration that never re-publishes, or a deliberate historical/audit lookup) carries a now-expired Seal Certificate and fails **Badge** pre-verification with `SEAL_VERIFICATION_FAILED`, even though the **Seal** signature is genuine. This breaks normal **Connection** verification for stale-but-`ACTIVE` agents.

We now validate the Seal Certificate **as-of the entry's own sealing time** instead of as-of "now." The sealing time is `payload.timestamp` (ISO-8601 with offset, e.g. `2026-06-16T12:57:00.735618+08:00`), which sits inside the raw `payload` object covered by the Seal's RFC 8785 JCS signature — it is authenticated and cannot be altered without breaking the signature. Concretely, the **Seal Validation Time** is `min(payload.timestamp, now)`: `SealVerifier` calls `leaf.checkValidity(asOf)` and sets `PKIXParameters.setDate(asOf)` so the whole chain (leaf → intermediate → root) is validated at that instant. A certificate that was valid when the entry was sealed verifies even if it has since expired; a signature whose timestamp falls *after* the certificate's `notAfter` still fails.

Rules:

- **Clamp to now.** `asOf = min(timestamp, now)`. A future-dated timestamp is validated at "now," preserving ADR 0011's "not-yet-valid leaf fails closed" guarantee and absorbing clock skew.
- **Missing / unparseable timestamp → fall back to now.** With no authenticated sealing time there is no basis to trust a past validity window, so verification degrades to today's strict behavior — never more lenient.
- **Strict lower bound.** `asOf` must lie within `[notBefore, notAfter]`. An entry timestamped before the certificate existed fails closed; in production this cannot happen, since CNNIC seals only with an already-issued certificate.
- Everything else in ADR 0011 is unchanged: `seal.certificate` is required, path-validation to the built-in **Seal CA Chain**, leaf Subject bound to `O=中国互联网络信息中心` + `OU=ATI`, the SHA-256withRSA allow-list (ADR 0009), and revocation checking disabled.

This applies to both `SealVerifier.verify(log)` and `verify(log, trustChain)`, so it covers Badge pre-verification in `BadgeVerificationService` uniformly. No new API, flag, or **VerificationStatus** — a rejected post-expiry signature still surfaces as `SEAL_VERIFICATION_FAILED`.

## Considered options

- **Ignore validity entirely — "the public key verifies the signature, so pass"** — rejected. Reopens a forgery window: a leaked/archived *expired* Seal private key could sign a brand-new entry today and pass, since that certificate still chains to the Seal CA and matches the Subject. Expiry is currently the only de-facto bound on a stale signing key (ADR 0011 deferred CRL/OCSP), and dropping it wholesale removes that bound.
- **Validate as-of the signed sealing timestamp (chosen)** — passes every legitimate historical entry while still rejecting a signature made after the certificate expired. The timestamp is inside the signed content, so it is authenticated rather than self-asserted out of band.
- **Fixed grace period after expiry (accept if expired within N days)** — rejected; a 1–2-year-old entry is far beyond any grace window, so it does not solve the stated problem.
- **Staleness cap (reject if `now - timestamp > N years`)** — rejected; breaks legitimate long-lived registrations (an agent may stay `ACTIVE` for years on one sealing) and contradicts supporting historical TL verification.
- **Anchor real publication time via Checkpoint / Merkle Proof now** — deferred, not rejected; see Consequences.

## Consequences

- `SealVerifier.verifySealWithCertificate` replaces `leaf.checkValidity()` with `leaf.checkValidity(asOf)`; `validateCertPath` adds `params.setDate(asOf)`. `asOf` is derived from the raw signed `payload` map (`log.getPayload().get("timestamp")`), parsed, clamped to now, and falling back to now when absent or unparseable.
- **Widened revocation gap (accepted).** Expiry was the de-facto exposure bound for a compromised Seal key. Under as-of validation, a leaked historical key can produce a *backdated* forged entry (timestamp inside that key's validity window) that verifies. Exploiting it additionally requires serving the forgery to the verifier — a MITM of the `ati-tl.cnnic.cn` TLS connection, or pointing the SDK at a rogue **Trusted TL Domain** — a high bar, and consistent with ADR 0011's decision to defer CRL/OCSP.
- **Future hardening.** The cryptographically complete fix is to anchor the entry's *real* publication time via a signed **Checkpoint** / **Merkle Proof**, which makes backdating impossible. Checkpoint verification is not on the Connection path today; recorded as a separate increment.
- Test fixtures must align the payload `timestamp` with the generated leaf's validity window; the expired-leaf case splits into "sealed in-window → passes" and "sealed after `notAfter` → fails."
- ADR 0011's "expired or not-yet-valid leaf fails closed" clause is amended by this ADR; its chain shape, Subject binding, and revocation deferral remain in force.
