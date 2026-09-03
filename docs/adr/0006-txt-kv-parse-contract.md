---
status: accepted
---

# Unordered KV TXT parse; Badge keys align with Discovery; Trusted TL Domain pins only baseUrl

Discovery (`_ati`) and Badge (`_ati-badge`) TXT records are semicolon-separated KV maps. Key order is not significant. This SDK implements `ati1` and `ati-badge1` only. Badge TXT uses the same keys as Discovery (`av`, `u`) — not the leftover `version` / `url` names. **Trusted TL Domain** constrains `TransparencyClient.baseUrl` only; verification takes the path from Badge `u=` and concatenates it with that baseUrl (Spec 7.1), so a tampered TXT host cannot redirect HTTP.

The full parse contract lives in `CONTEXT.md` (Discovery TXT Record, Badge, Trusted TL Domain). This ADR records why those rules exist.

## Considered options

- **Keep Badge keys `version=` / `url=`** — rejected; the KV dialect was updated to match Discovery (`av` / `u`) and the Badge parser was not. Dual-key compatibility would freeze both names in tests and parsers. ATI is not widely deployed; old keys are obsolete.
- **Accept every `ati{N}` / `ati-badge{N}` with current field semantics** — rejected as the upgrade story. Unknown keys on `ati1` already allow additive fields. Bumping `v=` means a breaking change; old SDKs must skip unimplemented family versions (`ati2`, `ati-badge2`) rather than misread them. Family recognition is `^ati[0-9]+$` and `^ati-badge[0-9]+$` (case-sensitive) so `ati-badge1` is never treated as Discovery.
- **Check Badge TXT `u=` host against Trusted TL Domain (in addition to baseUrl)** — rejected. Spec 7.1 already ignores the TXT host for the request. A second check duplicates the allowlist (`BadgeUrlValidator` vs `TrustedDomainRegistry`) and fails when TXT still points at legacy `tl.atiagent.cn` while the client uses `https://ati-tl.cnnic.cn`. DNS cannot steer traffic if the SDK never uses that host.
- **Require `av` to carry a `v` prefix** — rejected; both `v1.0.0` and `1.0.0` are published. Parsers strip a leading `v`/`V` before SemVer comparison. Missing or non-SemVer `av` still invalidates the record (`av` is required on both TXT types).
- **Drop Discovery `m=`** — rejected; it remains Discovery-only, optional, default `direct`, unknown values skip that record. Badge TXT has no `m=`.

## Consequences

- Discovery parse stays a KV map: case-sensitive keys, unknown keys ignored, duplicate keys last-wins, `u=` non-blank only, `p=` only `mcp` / `a2a` / `http-api`.
- Badge parse uses the same map rules and required `av` + `u`. Records with `version=` / `url=` and no `av` / `u` are invalid.
- `TransparencyClient` construction still requires `baseUrl` host ∈ Trusted TL Domain. Badge verification must not treat TXT `u=` host as the HTTP target or as a domain allowlist check.
- ADR-0001's "BadgeUrlValidator checks Badge URL hosts" no longer applies to TXT `u=`. ADR-0003's Discovery format string is unchanged at the field-name level; parse strictness is this ADR + `CONTEXT.md`.
