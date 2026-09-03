# ati-sdk-transparency

Transparency log module — fetches and verifies Badge entries (Seal, Merkle proof) from the CNNIC Transparency Log (TL) service. SCITT Receipt/Status Token verification infrastructure is present but **not yet integrated** into agent Connection flows.

## Key Classes

- `TransparencyClient` — TL service client (fetch badges, seals, Merkle proofs)
- `RootKeyManager` — Manages TL root public key for verification
- `TrustedDomainRegistry` — Registry of trusted TL domains

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
