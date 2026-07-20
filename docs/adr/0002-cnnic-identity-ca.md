---
status: accepted
---

# CNNIC operates IDCA and issues Identity Certificates

ATI agent identity in mTLS is proven by **Identity Certificates** — privately signed certificates carrying the agent's ATI Name in the URI SAN. These certificates are **issued by CNNIC** (China Internet Network Information Center), not by the RA (Alibaba Cloud ATI service).

During registration, the agent operator submits an **Identity CSR** via ATI Console. CNNIC validates the request and issues the Identity Certificate from its **IDCA** (Identity CA). CNNIC is the national regulatory authority; operating the private identity CA under its oversight provides public credibility for agent identity, distinct from arbitrary self-signed or vendor-operated CAs.

## Considered options

- **RA (Alibaba Cloud ATI) issues identity certificates** — rejected; separates registration (commercial cloud service) from trust infrastructure (national authority).
- **CNNIC issues via IDCA** — accepted; aligns identity trust with TL operations under the same regulatory body.

## Consequences

- Server-side mTLS validation uses `idca.trust-certificate` to trust CNNIC's identity CA root, not a generic ATI or Alibaba Cloud CA.
- **Server Certificates** remain operator-provided or ACME-issued — CNNIC does not issue transport-layer TLS certificates.
- Documentation and glossary refer to Identity Certificates as **CNNIC-issued**, not ATI-issued.
