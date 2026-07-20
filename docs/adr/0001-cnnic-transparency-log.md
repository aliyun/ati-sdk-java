---
status: accepted
---

# CNNIC operates the sole ATI Transparency Log

ATI Badge entries are stored in an append-only Transparency Log (TL) operated exclusively by CNNIC — not by Alibaba Cloud. The SDK default TL base URL is `https://ati-tl.cnnic.cn:8180`. The legacy hostname `tl.atiagent.cn` remains trusted for agents registered before the current endpoint.

Early SDK versions referenced Alibaba Cloud domains (`transparency.ati.aliyun.com`, `transparency.ati.ote-ati.aliyun.com`) as TL endpoints. Those domains were never production TL operators for ATI; they caused confusion with the RA (Alibaba Cloud ATI Console / OpenAPI), which is a separate system. The SDK removes those constants and trusted-domain entries.

## Considered options

- **Keep Alibaba Cloud TL domains as trusted fallbacks** — rejected; implies Alibaba operates the TL and invites misconfiguration.
- **CNNIC only, with legacy `tl.atiagent.cn`** — accepted; matches production reality and supports existing Badge DNS records.

## Consequences

- `TransparencyClient.CNNIC_BASE_URL` is the sole built-in production default; configure another base URL explicitly for non-production testing.
- `TrustedDomainRegistry` and `BadgeUrlValidator` trust only CNNIC TL hostnames by default.
- Badge DNS TXT records use the `_ati-badge` prefix only (legacy `_ra-badge` lookup removed).
