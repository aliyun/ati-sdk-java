# ATI Java SDK

> Agent 信任基础设施 (ATI) Java SDK — 通过 DNS 发现、DANE TLSA 验证和透明日志认证，实现安全的 Agent 间通信。

[English](README.md) | [中文](README.zh-CN.md)

## 特性

- **基于 DNS 的 Agent 发现** — 通过 ATI Name（`ati://v{version}.{agentHost}`）解析 Agent
- **DANE TLSA 验证** — 通过 DNS TLSA 记录验证服务器证书
- **Badge 验证** — 通过透明日志加密验证 Agent 注册信息
- **mTLS 安全连接** — 支持身份证书的双向 TLS
- **SCITT 透明性头** — 签名的透明性头，用于可审计的 Agent 交互
- **Spring Boot 自动配置** — 通过 `ati.sdk.*` 属性实现零配置集成

## 验证策略

| 策略 | DANE | Badge | 说明 |
|------|------|-------|------|
| `PKI_ONLY` | 禁用 | 禁用 | 仅标准 TLS |
| `BADGE_REQUIRED` | 禁用 | 必须 | 需要 Badge 验证（默认） |
| `DANE_AND_BADGE` | 必须 | 必须 | DANE 和 Badge 均需验证 |

## 验证时序图

### PKI_ONLY：标准 TLS（+ 服务端 IDCA 验证）

```mermaid
sequenceDiagram
    participant C as Client Agent
    participant S as Server Agent
    participant CA as System CA
    participant IDCA as IDCA Root CA

    Note over C,S: 客户端验证
    C->>S: 1. TLS 握手 (ClientHello)
    S->>C: 2. ServerHello + 服务器证书链
    C->>CA: 3. 验证服务器证书链
    CA->>C: 4. 链有效 ✓
    C->>S: 5. 完成 TLS 握手

    Note over C,S: 服务端验证（配置了 IDCA 时）
    C->>S: 6. 客户端身份证书 (mTLS)
    S->>IDCA: 7. 根据 IDCA 根证书链验证客户端证书
    IDCA->>S: 8. 客户端证书有效 ✓

    Note over C,S: 9. 连接建立
    C<->>S: 加密应用数据
```

### BADGE_REQUIRED：TLS + 透明日志验证

```mermaid
sequenceDiagram
    participant C as Client Agent
    participant DNS as DNS 服务器
    participant ATI as ATI 控制台 (OpenAPI)
    participant TL as CNNIC TL
    participant S as Server Agent

    Note over C,S: 客户端验证
    C->>ATI: 1. 发现 Agent (hostname, version)
    ATI->>C: 2. AgentDescriptor (host, badgeUrl)
    C->>TL: 3. 从 TL 获取 badge
    TL->>C: 4. Badge + Seal + Merkle Proof
    Note over C: 5. 验证 badge 签名和 seal
    C->>S: 6. mTLS 握手（客户端证书 + 服务器证书）
    Note over C: 7. 后验证：服务器证书哈希 == badge 哈希 ✓

    Note over C,S: 服务端验证
    Note over S: 8. 接收客户端身份证书
    Note over S: 9. 从证书 URI SAN 提取客户端 agentHost
    S->>DNS: 10. 查询 _ati-badge.{clientHost} TXT
    DNS->>S: 11. 客户端 badge URL
    S->>TL: 12. 从 TL 获取客户端 badge
    TL->>S: 13. 客户端 Badge + Seal + Merkle Proof
    Note over S: 14. 验证客户端证书指纹 == badge 哈希 ✓

    Note over C,S: 15. 连接建立
    C<->>S: 加密应用数据
```

### DANE_AND_BADGE：完整验证

```mermaid
sequenceDiagram
    participant C as Client Agent
    participant DNS as DNS 服务器
    participant ATI as ATI 控制台 (OpenAPI)
    participant TL as CNNIC TL
    participant S as Server Agent

    Note over C,S: 客户端验证
    C->>ATI: 1. 发现 Agent (hostname, version)
    ATI->>C: 2. AgentDescriptor (host, badgeUrl)
    C->>DNS: 3. 查询 _443._tcp.{serverHost} TLSA
    DNS->>C: 4. TLSA: 3 1 1 <server-cert-hash>
    C->>TL: 5. 从 TL 获取 badge
    TL->>C: 6. Badge + Seal + Merkle Proof
    Note over C: 7. 验证 badge 和 DANE TLSA
    C->>S: 8. mTLS 握手（客户端证书 + 服务器证书）
    Note over C: 9. 后验证：DANE 哈希 + Badge 哈希 + 证书 ✓

    Note over C,S: 服务端验证
    Note over S: 10. 接收客户端身份证书
    Note over S: 11. 从证书 URI SAN 提取客户端 agentHost
    S->>DNS: 12. 查询 _ati-badge.{clientHost} TXT
    DNS->>S: 13. 客户端 badge URL
    S->>DNS: 14. 查询 _ati-identity._tls.{clientHost} TLSA
    DNS->>S: 15. TLSA: 3 1 1 <client-cert-key-hash>
    S->>TL: 16. 从 TL 获取客户端 badge
    TL->>S: 17. 客户端 Badge + Seal + Merkle Proof
    Note over S: 18. 验证客户端证书指纹 == badge 哈希 ✓
    Note over S: 19. 验证客户端证书公钥 == TLSA 哈希 ✓

    Note over C,S: 20. 连接建立
    C<->>S: 加密应用数据
```

## 模块

| 模块 | 说明 |
|------|------|
| [`ati-sdk-core`](ati-sdk-core/README.md) | 配置、认证、HTTP、工具类 |
| [`ati-sdk-discovery`](ati-sdk-discovery/README.md) | 基于 DNS 的 Agent 解析 |
| [`ati-sdk-transparency`](ati-sdk-transparency/README.md) | 透明日志 + SCITT 验证 |
| [`ati-sdk-agent-client`](ati-sdk-agent-client/README.md) | 安全的 Agent 间连接 |
| [`ati-sdk-spring-boot-starter`](ati-sdk-spring-boot-starter/README.md) | Spring Boot 自动配置 |

## 安装

### Gradle

```kotlin
// Spring Boot（推荐，包含所有模块）
implementation("com.aliyun.ati:ati-sdk-spring-boot-starter:0.1.0")

// 或按需引入单个模块
implementation("com.aliyun.ati:ati-sdk-agent-client:0.1.0")     // 客户端连接
implementation("com.aliyun.ati:ati-sdk-discovery:0.1.0")         // Agent 发现
implementation("com.aliyun.ati:ati-sdk-transparency:0.1.0")      // 透明日志
```

### Maven

```xml
<dependency>
  <groupId>com.aliyun.ati</groupId>
  <artifactId>ati-sdk-spring-boot-starter</artifactId>
  <version>0.1.0</version>
</dependency>
```

## 快速开始

### Agent 注册

Agent 注册在[阿里云 ATI 控制台](https://ati.console.aliyun.com)完成。注册流程：

```
┌─────────────┐    ┌─────────────┐    ┌─────────────┐    ┌─────────────┐
│  生成密钥   │───▶│  提交 CSR   │───▶│  ACME + DNS  │───▶│   ACTIVE    │
│  和 CSR     │    │  到控制台   │    │  验证       │    │ (可发现)    │
└─────────────┘    └─────────────┘    └─────────────┘    └─────────────┘
```

1. **生成密钥对** — 为身份证书和服务器证书创建 RSA/EC 密钥对
2. **生成 CSR** — 创建证书签名请求（服务器 CSR + 包含 ATI Name 的身份 CSR）
3. **提交注册** — 在 ATI 控制台注册 agentHost、version、endpoints 和 CSR
4. **ACME 验证** — 添加 DNS TXT 记录证明域名所有权
5. **证书签发** — ATI 签发身份证书和服务器证书
6. **DNS 验证** — 添加 TLSA 和 badge DNS 记录
7. **激活** — Agent 可通过 ATI Name 发现

> **注意：** 所有步骤均在 ATI 控制台完成，注册过程不需要 SDK 代码。

### Agent 发现

通过阿里云 OpenAPI 解析 Agent 信息：

```java
import com.aliyun.ati.sdk.discovery.DnsAtiDiscoveryClient;
import com.aliyun.ati.sdk.auth.AccessKeyCredentialsProvider;
import com.aliyun.ati.sdk.discovery.AtiAgentDescriptor;

// 使用 AK/SK 创建发现客户端
DnsAtiDiscoveryClient client = DnsAtiDiscoveryClient.builder()
    .endpoint("alidns.aliyuncs.com")
    .credentialsProvider(new AccessKeyCredentialsProvider(ak, sk))
    .build();

// 按 hostname 和版本约束解析
AtiAgentDescriptor agent = client.discover("agent.example.com", "1.0.0");
System.out.println("Agent host: " + agent.getAgentHost());
System.out.println("Badge URL: " + agent.getBadgeUrl());

// 解析最新版本
AtiAgentDescriptor latest = client.discover("agent.example.com");

// 异步解析
CompletableFuture<AtiAgentDescriptor> future = client.discoverAsync("agent.example.com");
```

### Agent 间连接

使用可配置的验证级别连接其他 Agent：

```java
import com.aliyun.ati.sdk.agent.AtiVerifiedClient;
import com.aliyun.ati.sdk.agent.ConnectOptions;
import com.aliyun.ati.sdk.agent.VerificationPolicy;
import com.aliyun.ati.sdk.agent.AtiConnection;

// 创建客户端
AtiVerifiedClient client = AtiVerifiedClient.builder()
    .keyStorePath("/path/to/identity.p12", "password")
    .policy(VerificationPolicy.BADGE_REQUIRED)
    .build();

// 仅 PKI — 标准 HTTPS + CA 验证
AtiConnection conn = client.connect("https://agent.example.com",
    ConnectOptions.builder()
        .verificationPolicy(VerificationPolicy.PKI_ONLY)
        .build());

// Badge 验证（推荐）— 通过透明日志验证
AtiConnection conn = client.connect("https://agent.example.com",
    ConnectOptions.builder()
        .verificationPolicy(VerificationPolicy.BADGE_REQUIRED)
        .build());

// 完整验证 — DANE + Badge
AtiConnection conn = client.connect("https://agent.example.com",
    ConnectOptions.builder()
        .verificationPolicy(VerificationPolicy.DANE_AND_BADGE)
        .build());

// 使用 mTLS 客户端证书 + Bearer token
AtiConnection conn = client.connect("https://agent.example.com",
    ConnectOptions.builder()
        .verificationPolicy(VerificationPolicy.DANE_AND_BADGE)
        .clientCertPath(Path.of("/path/to/client.crt"), Path.of("/path/to/client.key"))
        .authProvider(HttpAuthHeadersProvider.bearer("token"))
        .build());
```

### Spring Boot 自动配置

`application.yml`（客户端）：

```yaml
ati:
  sdk:
    mode: client
    discovery:
      endpoint: alidns.aliyuncs.com
      access-key-id: ${ATI_AK}
      access-key-secret: ${ATI_SK}
    identity:
      certificate: /path/to/identity.crt
      private-key: /path/to/identity.key
    transparency:
      base-url: https://ati-tl.cnnic.cn:8180
    verification:
      policy: BADGE_REQUIRED
    client:
      dns-timeout: 5s
      connect-timeout: 10s
```

`application.yml`（服务端）：

```yaml
ati:
  sdk:
    mode: server
    server:
      certificate: /path/to/server.crt
      private-key: /path/to/server.key
      port: 443
      verification:
        policy: PKI_ONLY
      idca:
        trust-certificate: /path/to/idca-trust.pem
    transparency:
      base-url: https://ati-tl.cnnic.cn:8180
```

通过 `ati.sdk.mode` 控制启用哪一侧：

| 模式 | 客户端 Bean | 服务端 Bean |
|------|-----------|-----------|
| `client` | 是 | 否 |
| `server` | 否 | 是 |
| `both` | 是 | 是 |

## 构建

```bash
./gradlew clean build
```

环境要求：Java 17+、Gradle 8.5+

## 开源协议

[MIT](LICENSE)

## 贡献

参见 [CONTRIBUTING.md](CONTRIBUTING.md)
