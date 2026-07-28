# 02 — Spring 服务端 mTLS 接入 CRL

**Status:** ready-for-human

**Blocked by:** 01 — CDP 解析与 CRL 校验核心

**What to build:** 当服务端配置了 **IDCA** trust anchor 且客户端提交 Identity Certificate 时，在 TLS 握手路径启用 **Certificate Revocation**（`BASIC`/`ENHANCED`/`ADVANCED`；`NONE` 不触发）。嵌入式 Spring Boot 集成测试：mock 带 CDP 的 client cert + CRL 含该 serial → mTLS 握手被拒绝。

## Acceptance criteria

- [x] IDCA 已配置 + client cert 呈现 → TLS 层执行 CRL 检查
- [x] Server policy `NONE` → 不请求 client cert，CRL 不触发
- [x] 集成测试：revoked serial → mTLS 握手失败
- [x] 集成测试：valid serial + 无 CDP 链 → mTLS 可建立（CRL 跳过）
- [x] `./gradlew :ati-sdk-spring-boot-starter:test` 通过
