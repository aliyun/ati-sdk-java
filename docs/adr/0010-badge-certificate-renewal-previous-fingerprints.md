---
status: accepted
---

# Badge Certificate Renewal uses optional previous fingerprints (same-role OR)

During **Certificate Renewal**, a **Badge Entry** may carry the immediately previous fingerprint alongside the current one so peers still presenting the old certificate pass **Badge** verification. `payload.certificates` gains additive optional fields on `ATI-TL-V1`: `previousServerCertFingerprint` and `previousIdentityCertFingerprint`. Matching is **same-role OR** — a presented **Server Certificate** must hit current or previous server fingerprint; a presented **Identity Certificate** must hit current or previous identity fingerprint. The two previous fields are independently optional; the current fingerprint for that role remains required. CNNIC guarantees at most two certificates of the same role (current + immediately previous); previous is one slot, not a history list. The SDK does not time-out previous fingerprints — the window is the field's presence on the Badge Entry.

This is Badge-only and orthogonal to **Version Rotation** (union across Badge Entries) and to **DANE** (TLSA any-match; `previous*` is not copied into DANE). Older SDKs ignore the new keys and match current only.

## Considered options

- **Cross-role OR (any of the four fingerprints)** — rejected; would let an Identity Certificate satisfy Server Verification (and vice versa).
- **Previous fields must appear as a pair** — rejected; Server Certificate and Identity Certificate renew independently.
- **Previous alone can replace a missing current** — rejected; fail-closed. Previous is additive, not a substitute.
- **Renewal ignores Version Rotation and keeps only the latest `av` entry** — rejected; breaks peers still on an older agentVersion during overlap.
- **Feed `previous*` into DANE, or skip DANE while previous is present** — rejected; Advanced would collapse toward Enhanced. Operators who need Advanced during the overlap publish both TLSA records themselves.
- **Bump schema to `ATI-TL-V2`** — rejected; CNNIC locked `ATI-TL-V1`. Additive optional fields are enough; old SDKs already `ignoreUnknown`.
- **SDK TTL or `notAfter` on previous** — rejected; the SDK is a verifier, not the renewal policy engine. CNNIC owns the window.
- **Previous as an array of historical fingerprints** — rejected; CNNIC guarantees one overlap slot per role. A later renewal replaces the slot and drops the older certificate.
- **Reject the entry when previous equals current** — rejected; treat as a one-element set. Duplicate detection is not schema validation.

## Consequences

- Server Verification unions current ∪ previous server fingerprints per Badge Entry, then unions those sets across ACTIVE/DEPRECATED entries (existing Version Rotation behavior).
- Client Verification applies the same OR to identity fingerprints on the matched Badge Entry.
- Missing or blank previous means that role is not in a renewal window.
- Hitting previous is the same **Verification Result** as hitting current — not a distinct status.
- Un-upgraded SDKs fail closed on the previous certificate during the overlap; presenting the current certificate still succeeds.
