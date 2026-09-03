---
status: accepted
---

# CNNIC owns IDCA and issues Identity Certificates

ATI agent identity in mTLS is proven by **Identity Certificates** — privately signed certificates carrying the agent's ATI Name in the URI SAN. These certificates are **issued by CNNIC** from the **IDCA Intermediate**, not by the RA (Alibaba Cloud ATI service).

IDCA is a two-tier private PKI **owned by CNNIC**. Both tiers are CNNIC-named in production: the **IDCA Root** is `CN=CNNIC ATI RSA Root CA R1` (`O=CNNIC`) and the **IDCA Intermediate** that signs Identity Certificates is `CN=CNNIC ATI RSA CA 2026` (`O=CNNIC`). CNNIC commissions **UniTrust (SHECA)** to operate the chain's revocation and distribution infrastructure — the CRL / OCSP / CA-Issuers endpoints on `*.global.sheca.com` — not the Root's identity. (Corrected against the production certificate bytes: the earlier staging chain carried a UniTrust-named Root subject; production does not.)

During registration, the agent operator submits an **Identity CSR** via ATI Console. CNNIC validates the request and issues the Identity Certificate from the IDCA Intermediate. CNNIC remains the national regulatory authority; UniTrust (SHECA) operates revocation infrastructure and does not issue agent identity leaves.

## Considered options

- **RA (Alibaba Cloud ATI) issues identity certificates** — rejected; separates registration (commercial cloud service) from trust infrastructure (national authority).
- **A UniTrust-named Root subject** — rejected; the production Root is CNNIC-named (`CN=CNNIC ATI RSA Root CA R1`, `O=CNNIC`). UniTrust/SHECA operates the CRL/OCSP/AIA infrastructure, not the Root identity.
- **CNNIC owns both Root and Intermediate, delegating only revocation infrastructure to UniTrust/SHECA** — accepted; identity leaves stay CNNIC-issued under a CNNIC-named Root.

## Consequences

- Server-side mTLS validation trusts the **IDCA Chain** (CNNIC-named Root + CNNIC Intermediate), not a generic ATI or Alibaba Cloud CA.
- **Server Certificates** remain operator-provided or ACME-issued — CNNIC does not issue transport-layer TLS certificates.
- Documentation and glossary refer to Identity Certificates as **CNNIC-issued**, not ATI-issued or UniTrust-issued.
- The IDCA Root **is** CNNIC-named (`CN=CNNIC ATI RSA Root CA R1`); describe UniTrust/SHECA as the operator of the chain's CRL/OCSP/AIA infrastructure, not as the Root's subject or owner.
