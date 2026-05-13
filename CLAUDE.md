# ATI Java SDK

Agent Trust Infrastructure (ATI) Java SDK — 类似 GoDaddy ANS 的 Agent 注册/发现/安全连接 SDK。

## 参考实现

### ans-sdk-java (`./ans-sdk-java/`)

GoDaddy 的 ANS Java SDK，本项目的代码参考。结构：

- `ans-sdk-core` — 配置、认证、异常、HTTP、线程池（已参考完成 `ati-sdk-core`）
- `ans-sdk-crypto` — 密钥对生成、CSR 创建（Bouncy Castle）
- `ans-sdk-registration` — Agent 注册生命周期客户端
- `ans-sdk-discovery` — Agent 解析（按 hostname/version）
- `ans-sdk-transparency` — 透明日志 + SCITT 验证
- `ans-sdk-agent-client` — 安全 Agent-to-Agent 连接
- `ans-sdk-spring-boot-starter` — Spring Boot 自动配置

关键模式：Builder pattern、AWS 风格 CredentialsProvider、sync + async (CompletableFuture)、package-private service 层。

### ans-registry (`./ans-registry/`)

GoDaddy ANS Registry 的设计文档，本项目的架构设计参考。

- `DESIGN.md` — 核心架构规范（API、状态机、DNS 记录、证书模型、SCITT）
- `TRUST_INDEX_SPEC.md` — 信任评分规范
- `MAESTRO.md` — 安全威胁建模
- `pki/` — CA 证书链（OTE / Prod）

核心概念：
- 双证书模型：Server Cert（公有CA）+ Identity Cert（私有CA，版本绑定）
- 5 种 DNS 记录：`_ans` 发现、`_ans-badge` 徽章、TLSA 服务器、TLSA 身份、HTTPS/ECH
- 状态机：PENDING → PENDING_DNS → ACTIVE → DEPRECATED → REVOKED
- ANSName 格式：`ans://v{version}.{agentHost}`

## 项目结构

```
ati-java-sdk/
├── ati-sdk-core/          # 已完成：配置、认证、异常、HTTP、线程池
├── ans-sdk-java/          # 参考：GoDaddy ANS Java SDK
├── ans-registry/          # 参考：ANS Registry 设计文档
├── build.gradle.kts       # Gradle Kotlin DSL
├── settings.gradle.kts
└── gradle.properties
```

## 技术栈

- Java 17+
- Gradle 8.10 (Kotlin DSL)
- Group ID: `com.aliyun.ati`
- Jackson 2.16.1, SLF4J 2.0.9
- 测试: JUnit 5, Mockito, AssertJ

## 构建

```bash
gradle clean build
```
