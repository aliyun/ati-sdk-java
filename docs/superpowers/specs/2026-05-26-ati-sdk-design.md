# ATI Java SDK 设计文档

日期：2026-05-26

## 1. 背景与范围

ATI（Agent Trust Infrastructure）Java SDK 为 Agent 间的安全通信提供发现和连接能力。

**在范围内：**
- Agent 发现（Discovery）：ATI Client 通过 DNS 找到目标 Agent
- 安全连接（Secure Connection）：mTLS + 两层验证（DANE / Badge）
- Spring Boot 自动配置

**不在范围内：**
- Agent 注册——由外部 ATI Registry 负责
- 证书签发——注册后由 ATI Registry 颁发，业务方自行装入 keystore
- SCITT 离线验证——ATI TL 暂不支持，后续版本扩展

## 2. 角色定义

| 角色 | 含义 |
|---|---|
| **ATI Client** | 发现并调用 Agent 的一方 |
| **ATI Server** | 被发现、被调用的 Agent |

同一个服务可以同时是两种角色（`mode=both`）。

## 3. 模块结构

```
ati-sdk-core          （已完成）
  ├── 配置、认证、异常、HTTP、线程池
  └── + CertUtils（SHA-256 指纹计算，新增）

ati-sdk-discovery     依赖 core
  └── DNS 解析 _ati / _ati-badge TXT 记录，返回 AtiAgentDescriptor

ati-sdk-transparency  依赖 core
  └── BadgeVerificationService（透明日志查询 + 证书指纹比对）

ati-sdk-agent-client  依赖 core + discovery + transparency
  ├── VerificationPolicy（DANE/Badge 两层策略组合）
  ├── AtiVerifiedClient（ATI Client 主入口）
  └── ClientRequestVerifier（ATI Server 验证入站客户端）

ati-sdk-spring-boot-starter  依赖 agent-client
  └── 自动配置 ATI Client / Server Bean
```

## 4. Discovery 模块（ati-sdk-discovery）

### 4.1 ATIName 格式

```
ati://v{version}.{agentHost}
示例：ati://v1.my-agent.example.com
```

### 4.2 DNS 记录

ATI 使用两个独立的 TXT 记录，职责分离：

**发现记录**（指向 Agent 元数据端点）：
```
_ati.{agentHost}  TXT
内容示例：v=ati1; version=v1.0.0; url=https://my-agent.example.com/.well-known/ati/trust-card.json
```

| 字段 | 必填 | 说明 |
|---|---|---|
| `v` | 是 | 固定 `ati1` |
| `version` | 是 | Agent 版本（semver，带 `v` 前缀） |
| `url` | 否 | Trust Card 地址，默认 `/.well-known/ati/trust-card.json` |
| `mode` | 否 | `card`（默认）或 `direct`（直连，省略 url） |

**Badge 验证记录**（指向透明日志）：
```
_ati-badge.{agentHost}  TXT
内容示例：v=ati-badge1; version=v1.0.0; url=https://tl.ansagent.cn:8180/tl/agents/{uuid}
```

| 字段 | 必填 | 说明 |
|---|---|---|
| `v` | 是 | 固定 `ati-badge1` |
| `version` | 是 | 对应哪个 ACTIVE 版本 |
| `url` | 是 | 透明日志中该 Agent 的完整 URL（从中提取 agentId） |

### 4.3 核心类

| 类 | 职责 |
|---|---|
| `AtiName` | 解析 `ati://v{version}.{agentHost}` 格式 |
| `AtiAgentDescriptor` | 描述一个 Agent（host、version、透明日志 URL、agentId） |
| `AtiDiscoveryClient` | 接口 |
| `DnsAtiDiscoveryClient` | 实现，用 dnsjava 查 `_ati.{host}` TXT 记录，超时 5s |

返回结果供 `ati-sdk-agent-client` 直接使用，不包含任何验证逻辑。

## 5. Transparency 模块（ati-sdk-transparency）

### 5.1 透明日志 API

所有请求打向配置的 base URL（当前为 `https://tl.ansagent.cn:8180`，后续可能变更，通过配置项指定）。查询接口公开，无需认证：

| 接口 | 调用方 | 调用时机 | 用途 |
|---|---|---|---|
| `GET /tl/agents/{agentId}/logs/latest` | ATI Client | 每次连接时实时调用 | Badge 验证：状态 + 证书指纹 + Merkle 证明 + TL 封存签名 |
| `GET /tl/root-keys` | ATI Client | 首次使用时拉取，缓存 24h | 获取 TL 封存公钥，用于验证 seal 签名和 Merkle 证明（走 HTTPS，传输层保障安全） |

**Badge 验证响应关键字段：**
- `status` — Agent 当前状态（ACTIVE / REVOKED 等）
- `payload.certificates.serverCertFingerprint` — 预期服务端证书指纹（ATI Client 验证服务端用）
- `payload.certificates.identityCertFingerprint` — 预期 identity 证书指纹（ATI Server 验证入站客户端用）
- `merkleProof` — Merkle 包含证明（leafHash / leafIndex / treeSize / path / rootHash）
- `seal` — TL 封存签名（SHA-256withECDSA over JCS 规范化内容）

**URL 安全校验**：白名单域名通过配置项指定（当前默认 `tl.ansagent.cn`），允许非标准端口（当前 8180）。

### 5.2 核心类

| 类 | 职责 |
|---|---|
| `AtiTransparencyClient` | HTTP 客户端，封装上述两个接口 |
| `BadgeVerificationService` | `verifyServer(hostname)` / `verifyClient(X509Certificate)` |
| `CachingBadgeVerificationService` | Caffeine 缓存包装（正向 15min，负向 5min，上限 10,000 条） |
| `TlSealVerifier` | 验证 TL 封存签名（SHA-256withECDSA over JCS）+ Merkle 包含证明 |
| `RootKeyManager` | 拉取并缓存 TL 签名公钥（缓存 24h） |

## 6. Agent Client 模块（ati-sdk-agent-client）

### 6.1 验证策略

```
VerificationMode：DISABLED / ADVISORY / REQUIRED

VerificationPolicy 预定义组合（对应 Bronze/Silver/Gold 验证层级）：
  PKI_ONLY        全部 DISABLED（Bronze：仅 PKI CA 证书链）
  BADGE_REQUIRED  Badge=REQUIRED，DANE=DISABLED（Bronze+：有 TL 证明但无 DANE）
  DANE_REQUIRED   DANE=REQUIRED，Badge=DISABLED（Silver：DANE + DNSSEC）
  DANE_AND_BADGE  DANE+Badge=REQUIRED（Gold：DANE + 透明日志实时验证，推荐生产）
```

### 6.2 ATI Client 侧连接流程

```
AtiVerifiedClient.connect(AtiName, ConnectOptions)

Pre-verify（TLS 握手前，并行执行）：
  ├── DANE：DNS 查 _tlsa.{port}.{host} 获取 TLSA 记录
  └── Badge：_ati-badge.{host} TXT → 透明日志 GET /tl/agents/{id}/logs/latest

Post-verify（TLS 握手后，本地完成）：
  └── 比对实际证书指纹 vs DANE/Badge 预期值
      Badge 还需验证 seal 签名 + Merkle 包含证明
```

`CertificateCapturingTrustManager` 在 TLS 握手时拦截并保存服务端证书链。

### 6.3 ATI Server 侧

| 类 | 职责 |
|---|---|
| `ClientRequestVerifier` | 验证入站客户端：比对 mTLS 客户端证书指纹是否在 TL 注册记录中 |

## 7. Spring Boot Starter（ati-sdk-spring-boot-starter）

### 7.1 配置项

```properties
ati.sdk.mode=client                    # client / server / both
ati.sdk.transparency.base-url=https://tl.ansagent.cn:8180
ati.sdk.verification.policy=DANE_AND_BADGE

# ATI Client 侧
ati.sdk.client.dns-timeout=5s
ati.sdk.client.connect-timeout=10s
ati.sdk.client.mtls.keystore=classpath:client-keystore.p12
ati.sdk.client.mtls.keystore-password=***

# ATI Server 侧
ati.sdk.server.mtls.keystore=classpath:server-keystore.p12
ati.sdk.server.mtls.keystore-password=***
```

### 7.2 自动配置类

| 类 | 激活条件 | 注册的 Bean |
|---|---|---|
| `AtiClientAutoConfiguration` | `mode=client` 或 `both` | `AtiTransparencyClient`、`RootKeyManager`、`BadgeVerificationService`、`AtiVerifiedClient` |
| `AtiServerAutoConfiguration` | `mode=server` 或 `both` | `AtiTransparencyClient`、`RootKeyManager`、`BadgeVerificationService`、`ClientRequestVerifier` |

不强依赖 `spring-web`，通过可选依赖适配 Servlet / WebFlux。

## 8. 技术依赖

| 依赖 | 用途 |
|---|---|
| `dnsjava` | DNS TXT / TLSA 查询，DNSSEC 验证 |
| `Bouncy Castle` | 证书指纹计算、ECDSA 签名验证（TL seal）、Merkle 证明计算 |
| `Caffeine` | Badge 验证结果缓存、root-key 缓存 |
| `Jackson` | 透明日志 API 响应解析 |
| `spring-boot-autoconfigure` | Starter 自动配置 |
