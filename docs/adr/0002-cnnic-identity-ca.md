---
status: accepted
---

# CNNIC owns IDCA and issues Identity Certificates

ATI agent identity in mTLS is proven by **Identity Certificates** — privately signed certificates carrying the agent's ATI Name in the URI SAN. These certificates are **issued by CNNIC** from the **IDCA Intermediate**, not by the RA (Alibaba Cloud ATI service).

IDCA is a two-tier private PKI **owned by CNNIC**. CNNIC **commissions UniTrust** to operate the **IDCA Root**; CNNIC itself operates the **IDCA Intermediate** that signs Identity Certificates. The Root's subject is UniTrust, not CNNIC — that is the delegated operator, not a second identity CA.

During registration, the agent operator submits an **Identity CSR** via ATI Console. CNNIC validates the request and issues the Identity Certificate from the IDCA Intermediate. CNNIC remains the national regulatory authority; UniTrust does not issue agent identity leaves.

## Considered options

- **RA (Alibaba Cloud ATI) issues identity certificates** — rejected; separates registration (commercial cloud service) from trust infrastructure (national authority).
- **CNNIC issues via IDCA, operating both Root and Intermediate itself** — rejected for the Root; CNNIC commissioned UniTrust to operate the IDCA Root.
- **CNNIC issues via IDCA Intermediate under a UniTrust-operated Root** — accepted; identity leaves stay CNNIC-issued; Root operation is delegated.

## Consequences

- Server-side mTLS validation trusts the **IDCA Chain** (UniTrust-operated Root + CNNIC Intermediate), not a generic ATI or Alibaba Cloud CA, and not a CNNIC-named root.
- **Server Certificates** remain operator-provided or ACME-issued — CNNIC does not issue transport-layer TLS certificates.
- Documentation and glossary refer to Identity Certificates as **CNNIC-issued**, not ATI-issued or UniTrust-issued.
- Do not describe the IDCA Root as "the CNNIC root"; say **IDCA Root** (UniTrust-operated, CNNIC-commissioned).
