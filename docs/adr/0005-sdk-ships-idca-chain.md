---
status: accepted
---

# SDK ships the production IDCA Chain as default server trust material

Server-side **Client Verification** needs a private trust store: public CAs must not validate Identity Certificates. The production **IDCA Chain** is exactly two certificates — **IDCA Root** (`CN=CNNIC ATI RSA Root CA R1`, CNNIC-owned; UniTrust/SHECA operates its CRL/OCSP infrastructure) plus **IDCA Intermediate** (`CN=CNNIC ATI RSA CA 2026`, CNNIC). The SDK ships that pair and loads both as the Server Agent's default trust material when **Verification Policy** is not None. Operators no longer have to supply a PEM path to enable verification.

A Server Agent may point `trust-certificate` at another two-certificate chain (a **Test IDCA Chain**, or a rotated production pair). That override **replaces** the shipped chain entirely — it never merges. Rotation of the Intermediate is a hard cutover via override; the shipped pair updates in a later SDK release. The shipped chain is server-trust only: it is not attached to a Client Agent's outbound Identity Certificate.

## Considered options

- **Operator always supplies the chain path** — rejected; production trust would drift, and `ENHANCED`/`ADVANCED` would fail closed until every operator copied the same PEM.
- **Ship Root only; require the client to send the Intermediate** — rejected; Identity Certificate keystores often contain only the leaf, and TLS would fail before Badge/DANE.
- **Override merges with the shipped chain** — rejected; a production server that also trusts the Test IDCA Chain would accept test-issued identity.
- **Chain is one Root plus N Intermediates** — rejected; the production chain is always exactly two certificates. Dual-issuance during rotation is out of scope for a single process.
- **Also inject the Intermediate into Client Agent outbound keystores** — rejected; outbound material stays the operator-provided Identity Certificate. The server already trusts the full chain, so a leaf-only client can complete mTLS.

## Consequences

- `NONE` skips Client Verification and does not load the IDCA Chain. `BASIC` and above use the shipped pair unless replaced.
- `ati.sdk.server.idca.trust-certificate` becomes optional. Unset means the shipped production chain; set means replace with that file's two certificates.
- Test and local demos replace the shipped chain with the **Test IDCA Chain**; they must not use the production pair as a convenience default in automated tests that need the ANS test CA.
- A production Server Agent that needs a new Intermediate before the next SDK release uses the override path. Old and new identity leaves cannot both verify in the same process.
