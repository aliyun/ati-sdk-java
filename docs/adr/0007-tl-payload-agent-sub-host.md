---
status: accepted
---

# Consume CNNIC-locked TL `agentHost` / `agentSubHost` mapping

CNNIC locked Badge Entry payload host fields: `payload.agentHost` is the **Access Hostname**; `payload.agentSubHost` is the **Identity Hostname** in Shared Domain Mode and is empty in Independent Domain Mode. The SDK does not rename those JSON keys. Domain language stays **Identity Hostname** / **Access Hostname**. Derived identity is `agentSubHost` when non-blank, otherwise `agentHost`. `ATI-TL-V1` is unchanged; `agentSubHost` is optional.

Keeping `payload.agentHost` as Identity Hostname (and adding `accessHost`) was rejected because CNNIC already ships the inverted names. Teaching `agentHost` / `agentSubHost` as a third hostname pair was rejected in ADR-0003. `TransparencyLog.getAgentHost()` therefore returns derived identity (same leftover meaning as `AgentDetail.getAgentHost()`), not the JSON field. Badge verification compares Identity Hostname only — not Access Hostname, and not the RA first-level-subdomain rule.

This supersedes ADR-0003's claim that TL JSON `agentHost` is identityHost. Discovery `getAgentHost()` is still identityHost.
