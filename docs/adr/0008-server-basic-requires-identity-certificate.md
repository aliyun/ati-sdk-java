---
status: accepted
---

# Server Basic requires an Identity Certificate at TLS

Server-side **None** and **Basic** used to look the same when the Client Agent presented no **Identity Certificate**: None never asked; Basic asked with `want`, so a missing certificate still completed the handshake. That collapsed L0 and L1. Server **Basic** now requires the Identity Certificate (`need`), same as **Enhanced** / **Advanced**. `client-auth` stays derived from **Verification Policy** only — no override back to `want`. Anonymous TLS is **None** only.

Client-side Basic is unchanged: outbound Identity Certificate stays optional; the **peer** Server Agent's policy decides whether presentation is required. Application-layer **Client Verification** (ATI Name in the URI SAN; no Badge/DANE at Basic) is still invoked by the Server Agent application, not by the Spring starter.

## Considered options

- **Keep `want`; reject only in application-layer Client Verification** — rejected; handshake still succeeds without an Identity Certificate, so None and Basic collapse again if the application never calls `ClientRequestVerifier`.
- **Allow operators to override Basic back to `want`** — rejected; the policy name would again mean optional identity, which is None.
- **Force Client Agents with Basic to always send an Identity Certificate** — rejected; presentation is a server requirement. A Client Agent with Basic must still be able to talk to None or non-ATI HTTPS without a client keystore.
