---
status: accepted
---

# Seal verification anchors on the Seal CA Chain, not the embedded publicKey

Badge pre-verification previously verified the **Seal** signature with the `publicKey` embedded in the same TL response — a self-asserted key that proves integrity but not authenticity: anyone forging a response could embed their own key + signature. CNNIC now attaches a **Seal Certificate** (`seal.certificate`) to each Seal. The SDK verifies the Seal signature with the public key inside that certificate, and path-validates the certificate to a built-in **Seal CA Chain** (a UniTrust-named root + intermediate). `seal.certificate` is now required; a Seal carrying only `publicKey` fails closed, and the `publicKey` field is no longer read. The SHA-256withRSA algorithm allow-list from ADR 0009 is unchanged.

The chain is three-tier: **Seal CA Root** (`O=UniTrust, CN=UCA RSA Non-Public Root CA - G1`, RSA-4096, →2043-04) → **Seal CA Intermediate** (`O=UniTrust, CN=UCA RSA Non-Public CA - SHA256 - G1`, RSA-2048, `CA:TRUE pathlen:0`, →2033-04) → **Seal Certificate** leaf (`O=中国互联网络信息中心, OU=ATI, CN=cnnic-ati-tl-service`, RSA-3072, ~1-year validity, rotated; it is also the TL service's own TLS server certificate, EKU `TLS Web Server/Client Authentication`). The SDK ships root + intermediate (mirroring the IDCA Chain) and builds a PKIX `CertPath` from the response leaf to the built-in root. Seals are signed per-response, so the leaf's validity is enforced at verification time — an expired or not-yet-valid leaf fails closed. Because the Seal CA is a **shared** UniTrust CA, chain validation alone would let any certificate under it impersonate the TL signing cert; the SDK therefore also binds the leaf Subject to `O=中国互联网络信息中心` + `OU=ATI`. EKU is not enforced (Java PKIX does not check EKU by default, and this leaf's EKU is TLS-oriented, not code-signing).

Revocation (CRL/OCSP) is out of scope for this change: the leaf's ~1-year rotation bounds the exposure window, and Badge pre-verification currently has no dependency on `sheca.com` being reachable — a fail-closed CRL fetch would couple every Badge check to that availability. The path-validation seam leaves room to add revocation later.

## Considered options

- **Keep verifying with the embedded `publicKey`; add `certificate` only as metadata** — rejected; leaves the self-asserted-key forgery surface intact and wastes the CA anchor.
- **Prefer `certificate`, fall back to `publicKey` when absent** — rejected; a forger simply omits `certificate` to revert to self-asserted mode, hollowing out the upgrade. `certificate` is required, fail-closed.
- **Ship only the Seal CA Root; require the response to carry leaf + intermediate** — rejected; couples every verification to CNNIC always sending the intermediate, and a leaf-only response could not be path-validated. Shipping root + intermediate mirrors ADR 0005's IDCA Chain.
- **Ship only the Root; fetch the Intermediate via AIA (`certs.sheca.com`)** — rejected; adds a runtime network dependency to Badge pre-verification, inconsistent with the fail-closed posture.
- **Anchor on the chain without binding the leaf Subject** — rejected; the UniTrust Seal CA is shared, so any certificate chaining to it with KU `digitalSignature` could forge a Seal.
- **Pin the leaf certificate / public key** — rejected; the leaf rotates ~yearly, forcing an SDK release every rotation.
- **Check CRL/OCSP now** — deferred, not rejected; recorded as a future increment (see above).

## Consequences

- `Seal` model gains a `certificate` field (previously dropped by `@JsonIgnoreProperties(ignoreUnknown=true)`); `SealVerifier` requires it and stops reading `publicKey`.
- New built-in trust material in `ati-sdk-transparency` — a `SealTrustChain` loader mirroring `IdcaChain`: shipped `seal-ca-chain.crt` (root + intermediate) plus optional override `ati.sdk.transparency.seal.trust-certificate` (replace, never merge). Placed in `ati-sdk-transparency` because `SealVerifier` lives there and `ati-sdk-agent-client` depends on it, not the reverse.
- Any chain-validation failure (missing `certificate`, path build failure, expiry, Subject mismatch, signature mismatch, trust-anchor load failure) yields `SEAL_VERIFICATION_FAILED` and fails Badge pre-verification.
- Seal CA Intermediate expiry (2033-04) is a hard cutover via the override before the next SDK release ships a renewed pair — same operational shape as IDCA Intermediate rotation.
- Tests must assert the shipped chain by exact CN (`UCA RSA Non-Public Root CA - G1` / `UCA RSA Non-Public CA - SHA256 - G1`) to block pre-release/test chains from being embedded — the same guard applied to the IDCA Chain.
- ADR 0009's "verification uses the per-response embedded publicKey" is superseded by this decision; its SHA-256withRSA-only allow-list remains in force.

> **Update (ADR 0012):** the "an expired or not-yet-valid leaf fails closed" clause above is amended. The **Seal Certificate** is now validated **as-of the entry's signed sealing time** — the **Seal Validation Time** `min(payload.timestamp, now)` — rather than at verification time. A historical **Badge Entry** whose leaf has expired *since* it was sealed therefore still verifies, while a signature timestamped after the leaf's `notAfter` still fails closed, and a missing timestamp falls back to "now." The chain shape, leaf Subject binding (`O=中国互联网络信息中心` + `OU=ATI`), SHA-256withRSA allow-list, and disabled revocation checking all remain in force.
