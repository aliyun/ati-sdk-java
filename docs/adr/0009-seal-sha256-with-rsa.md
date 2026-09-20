---
status: accepted
---

# CNNIC production Seal is SHA-256withRSA only

CNNIC specifies SHA-256withRSA as the production **Seal** signature algorithm. The SDK hard-allow-lists that algorithm: `signatureAlgorithm` must be SHA-256withRSA (normalized); missing or any other value — including SHA-256withECDSA — fails **Badge** pre-verification. Verification still uses the per-response embedded `publicKey`, not **TL Root Key**.

This applies to Seal only. **SCITT Header** Receipt/Status Token verification remains ES256. Checkpoint and **IDCA** signing are unchanged.

## Considered options

- **Follow `signatureAlgorithm` in the Seal JSON (default RSA)** — rejected; leaves an algorithm-substitution surface and makes the CNNIC production contract optional.
- **Accept both SHA-256withRSA and SHA-256withECDSA during transition** — rejected; dual algorithms keep ECDSA as a production path after CNNIC locked RSA.
- **Pin a CNNIC production RSA public key or `/root-keys`** — rejected for this change; trust-anchor replacement is a separate decision. Seal continues to verify with the embedded `publicKey`.

> **Update (ADR 0011):** the deferred trust-anchor replacement has since happened. Seal verification now uses the public key inside `seal.certificate`, path-validated to the built-in **Seal CA Chain**, instead of the response-embedded `publicKey` (which is no longer read; a Seal without `seal.certificate` fails closed). This ADR's SHA-256withRSA-only allow-list remains in force — only the "verifies with the embedded publicKey" statements above are superseded.
