# ati-sdk-transparency

Transparency log module — fetches and verifies Badge entries (Seal, Merkle proof) from the CNNIC Transparency Log (TL) service. SCITT Receipt/Status Token verification infrastructure is present but **not yet integrated** into agent Connection flows.

## Key Classes

- `TransparencyClient` — TL service client (fetch badges, seals, Merkle proofs)
- `RootKeyManager` — Manages TL root public key for verification
- `BadgeUrlValidator` — Validates badge URLs against trusted domains
- `TrustedDomainRegistry` — Registry of trusted TL domains

## Transparency Log

The TL is **operated by CNNIC only** — there is no separate Alibaba Cloud TL service. Agent registration is managed by RA (Alibaba Cloud ATI); Badge records are stored in CNNIC TL.

Trusted CNNIC TL domains:

- `ati-tl.cnnic.cn` — current production (see `TransparencyClient.CNNIC_BASE_URL`)
- `tl.atiagent.cn` — legacy CNNIC hostname

## Usage

```java
TransparencyClient client = TransparencyClient.builder()
    .baseUrl(TransparencyClient.CNNIC_BASE_URL)   // https://ati-tl.cnnic.cn:8180
    .skipTlsVerification(false)
    .build();

TransparencyLog log = client.getAgentTransparencyLog(agentId);
```

## Dependencies

- `ati-sdk-core`
- BouncyCastle 1.77 (cryptography)
- Caffeine 3.1.8 (caching)
