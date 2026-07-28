# 01 — CDP 解析与 CRL 校验核心

**Status:** ready-for-human

**Blocked by:** None — can start immediately

**What to build:** 从 Identity Certificate 链读取 **CDP**（leaf → issuer），HTTP 拉取 **CRL**，验证 CRL 签名并检查 client cert serial 是否被 **Certificate Revocation** 撤销；缓存 CRL（`nextUpdate` 驱动，最长 12h 刷新）。无 CDP 时跳过 CRL；有 CDP 时拉取/校验失败 fail-closed。

## Acceptance criteria

- [x] CDP 从 leaf Identity Certificate 读取；无 CDP 时从 issuing CA 读取
- [x] 链上无任何 CDP → 跳过 CRL 检查（debug 日志），连接不因 CRL 失败
- [x] serial 在 CRL 上 → 拒绝（Certificate Revocation）
- [x] serial 不在 CRL 上 → CRL 检查通过
- [x] 有 CDP 但 CRL HTTP 失败、签名无效或无法解析 → fail-closed
- [x] CRL 缓存遵循 `nextUpdate`，且最长 12h 强制刷新
- [x] 测试仅使用 mock CDP/CRL fixture，无生产配置 CRL URL
- [x] `./gradlew :ati-sdk-agent-client:test`（或放置模块）通过
