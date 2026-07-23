# ATI SDK 示例

本目录包含独立示例，演示 ATI（Agent Trust Infrastructure）验证与各种协议和 SDK 的集成。

## 示例

| 示例 | 说明 | SDK 集成 |
|------|------|----------|
| [http-api](http-api/) | 使用 `AtiClient` 的简单 HTTP API | 仅 ATI SDK |
| [mcp-client](mcp-client/) | MCP（Model Context Protocol）| Anthropic MCP SDK |

## 快速开始

```bash
# 构建所有示例
./gradlew :ati-sdk-agent-client:examples:http-api:build
./gradlew :ati-sdk-agent-client:examples:mcp-client:build

# 运行示例（需要目标服务器）
./gradlew :ati-sdk-agent-client:examples:http-api:run
./gradlew :ati-sdk-agent-client:examples:mcp-client:run

# 指定服务器 URL 运行
./gradlew :ati-sdk-agent-client:examples:http-api:run --args="https://your-agent.example.com:8443"
```

## 前置条件

1. **ATI 注册 Agent** — 在 [ATI 控制台](https://dnsnext.console.aliyun.com/ati/agents)注册并拥有 HTTPS 端点的 Agent
2. **DANE 验证**（可选）— Agent 主机名已配置 TLSA DNS 记录
3. **Badge 验证**（可选）— Agent 已在 ATI 透明日志（CNNIC TL）中注册
4. **MCP 示例** — 需要包含身份证书的客户端 PKCS12 keystore（见下文）

## 验证策略

所有示例支持不同的 ATI 验证策略：

| 策略 | TLS | DANE | Badge | 说明 |
|------|-----|------|-------|------|
| `NONE` (L0) or `BASIC` (L1) | ✓ | - | - | 标准 HTTPS，使用系统信任库 |
| `ENHANCED` | ✓ | - | ✓ | 需要透明日志验证（默认） |
| `ADVANCED` | ✓ | ✓ | ✓ | 同时需要 DANE 和 Badge 验证 |

## 集成模式

### 模式 1：高级 API（AtiClient）

使用 `AtiClient` 的最简方式：

```java
AtiClient client = AtiClient.builder()
    .connectTimeout(Duration.ofSeconds(10))
    .build();

AgentConnection conn = client.connect(
    "https://agent.example.com",
    ConnectOptions.builder()
        .verificationPolicy(VerificationPolicy.ENHANCED)
        .transparencyClient(TransparencyClient.builder()
            .baseUrl(TransparencyClient.CNNIC_BASE_URL).build())
        .build());

HttpApiClient api = conn.httpApiAt(serverUrl);
String response = api.get("/health");
```

### 模式 2：低级集成（AtiVerifiedClient + mTLS）

适用于接受自定义 `SSLContext` 的 SDK（如 MCP SDK）：

```java
// 1. 创建带 mTLS keystore 的 AtiVerifiedClient
try (AtiVerifiedClient atiClient = AtiVerifiedClient.builder()
        .keyStorePath("/path/to/client.p12", "changeit")
        .transparencyClient(TransparencyClient.builder()
            .baseUrl(TransparencyClient.CNNIC_BASE_URL).build())
        .policy(VerificationPolicy.ENHANCED)
        .build()) {

    // 2. 连接并执行预验证（DANE/Badge 查询）
    try (AtiConnection connection = atiClient.connect(serverUrl)) {

        // 3. 使用 ATI SSLContext 创建 SDK 客户端
        HttpClientStreamableHttpTransport transport = HttpClientStreamableHttpTransport
            .builder(serverUrl)
            .customizeClient(b -> b.sslContext(atiClient.sslContext()))
            .build();

        // 4. 初始化 SDK 客户端（触发 TLS 握手）
        McpSyncClient mcpClient = McpClient.sync(transport).build();
        mcpClient.initialize();

        // 5. 后验证服务器证书
        VerificationResult result = connection.verifyServer();
        if (!result.isSuccess()) {
            throw new SecurityException("ATI 验证失败: " + result.reason());
        }

        // 6. 使用已验证的连接
        var tools = mcpClient.listTools();
    }
}
```

## 创建客户端 Keystore

对于需要 mTLS 的示例（mcp-client），需要包含身份证书的 PKCS12 keystore：

```bash
# 从 PEM 文件生成（身份证书 + 私钥）：
openssl pkcs12 -export -in cert.pem -inkey key.pem -out client.p12 -name client -password pass:changeit

# 如需包含 CA 链：
openssl pkcs12 -export -in cert.pem -inkey key.pem -certfile ca.pem -out client.p12 -name client
```

## 从源码构建

这些示例是 Gradle 子项目，从根目录构建：

```bash
./gradlew :ati-sdk-agent-client:examples:http-api:build
```

## 依赖

| 示例 | 额外依赖 |
|------|----------|
| http-api | 无（仅使用 SDK） |
| mcp-client | `io.modelcontextprotocol.sdk:mcp:1.1.2` |
