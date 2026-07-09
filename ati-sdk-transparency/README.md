# ati-sdk-transparency

Transparency log module — fetches and verifies transparency log entries and SCITT headers from the ATI Transparency Log (TL) service.

## Key Classes

- `AtiTransparencyClient` — TL service client (fetch badges, seals, Merkle proofs)
- `RootKeyManager` — Manages TL root public key for verification
- `BadgeUrlValidator` — Validates badge URLs against trusted domains
- `TrustedDomainRegistry` — Registry of trusted TL domains

## Trusted Domains

- `transparency.ati.aliyun.com` (Production)
- `transparency.ati.ote-ati.aliyun.com` (OTE)
- `tl.atiagent.cn` (CNNIC TL — legacy)
- `ati-tl.cnnic.cn` (CNNIC TL — current)

## Usage

```java
AtiTransparencyClient client = AtiTransparencyClient.builder()
    .baseUrl("https://ati-tl.cnnic.cn:8180")
    .skipTlsVerification(false)
    .build();

TransparencyLogResponse response = client.getTransparencyLog(badgeUrl);
```

## Dependencies

- `ati-sdk-core`
- BouncyCastle 1.77 (cryptography)
- Caffeine 3.1.8 (caching)
