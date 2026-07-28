# 03 — 双轨回归：CRL 与 Registration Revocation

**Status:** ready-for-agent

**Blocked by:** 02 — Spring 服务端 mTLS 接入 CRL

**What to build:** 证明 **Certificate Revocation**（CRL，TLS 层）与 **Registration Revocation**（Badge `REVOKED`/`EXPIRED`，Client Verification 层）互补、互不替代。`DefaultClientRequestVerifier` 现有 Badge/DANE 行为无回归。

## Acceptance criteria

- [x] CRL 通过 + TL Badge Registration Status `REVOKED` → Client Verification 拒绝连接
- [x] serial 在 CRL 上 → TLS 层拒绝（无需依赖 Badge 路径拦截）
- [x] ENHANCED/ADVANCED server policy 下双轨均生效；Badge 逻辑未被 CRL 实现绕过或移除
- [x] AC2：`AtiIdcaCrlBadgeDualTrackIntegrationTest` 验证 mTLS CRL 通过后 Badge 仍执行
- [x] 相关集成/回归测试绿
