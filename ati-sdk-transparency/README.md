# ati-sdk-transparency

Transparency log module — fetches and verifies Badge entries (Seal, Merkle proof) from the CNNIC Transparency Log (TL) service. SCITT Receipt/Status Token verification infrastructure is present but **not yet integrated** into agent Connection flows.

## Key Classes

- `TransparencyClient` — TL service client (fetch badges, seals, Merkle proofs)
- `RootKeyManager` — Manages TL root public key for verification
- `TrustedDomainRegistry` — Registry of trusted TL domains
- `BadgeVerificationService` — Badge pre-verification (Seal + Merkle) for a hostname
- `SealVerifier` — Verifies a Seal's signature and its `seal.certificate` against a `SealTrustChain`
- `SealTrustChain` — The Seal CA Chain (Root + Intermediate) the SDK trusts when path-validating a Seal Certificate

## Transparency Log

The TL is **operated by CNNIC only** — there is no separate Alibaba Cloud TL service. Agent registration is managed by RA (Alibaba Cloud ATI); Badge records are stored in CNNIC TL.

Trusted CNNIC TL domains:

- `ati-tl.cnnic.cn` — current production (see `TransparencyClient.CNNIC_BASE_URL`)
- `tl.atiagent.cn` — legacy CNNIC hostname

## Badge TXT sample

`_ati-badge.{identityHost}` — semicolon-separated KV; this SDK parses **`ati-badge1`** only:

```
_ati-badge.abc123.bailian.aliyun.com.  TXT  "v=ati-badge1; av=v1.0.0; u=https://ati-tl.cnnic.cn/tl/agents/6bf2b7a9-1383-4e33-a945-845f34af7526"
```

Verification extracts the path from `u=` and requests `TransparencyClient.baseUrl` + that path. The Badge TXT `u=` host is not the HTTP target.

## Seal verification

A Badge Entry's Seal proves the TL body was published by CNNIC. Verification is **certificate-based** (ADR-0011):

- The Seal **must** carry `seal.certificate` — the leaf Seal Certificate. The legacy self-asserted `seal.publicKey`-only path is removed; a Seal without `seal.certificate` fails closed with `SEAL_VERIFICATION_FAILED`.
- `SealVerifier` path-validates that leaf (`leaf → Intermediate → Root`) against a `SealTrustChain`, enforces leaf validity, binds the leaf Subject to `O=中国互联网络信息中心` + `OU=ATI`, and checks the signature over the JCS (RFC 8785) canonical content with `SHA-256withRSA` (ADR-0009).
- `SealVerifier.verify(log)` anchors on `SealTrustChain.shipped()` — the SDK-shipped production Seal CA Chain (Root + Intermediate). `SealVerifier.verify(log, sealTrustChain)` accepts an injected chain.
- Operators replace the shipped chain without an SDK upgrade via the Spring property `ati.sdk.transparency.seal.trust-certificate` (a two-certificate Root + Intermediate PEM). Any chain failure — path, expiry, Subject, signature, or anchor load — yields `SEAL_VERIFICATION_FAILED` and fails Badge pre-verification.

Seal verification runs only at Badge policies (`ENHANCED`/`ADVANCED`); `NONE`/`BASIC` do not fetch or verify Badges.

## Usage

```java
TransparencyClient client = TransparencyClient.builder()
    .baseUrl(TransparencyClient.CNNIC_BASE_URL)   // https://ati-tl.cnnic.cn
    .skipTlsVerification(false)
    .build();

TransparencyLog log = client.getAgentTransparencyLog(agentId);
```

## Dependencies

- `ati-sdk-core`
- BouncyCastle 1.77 (cryptography)
- Caffeine 3.1.8 (caching)
