# ATI SDK Examples

This directory contains standalone examples demonstrating ATI (Agent Trust Infrastructure) verification
integration with various protocols and SDKs.

## Examples

| Example | Description | SDK Integration |
|---------|-------------|-----------------|
| [http-api](http-api/) | Simple HTTP API using `AtiClient` | ATI SDK only |
| [mcp-client](mcp-client/) | MCP (Model Context Protocol) | Anthropic MCP SDK |

## Quick Start

```bash
# Build all examples
./gradlew :ati-sdk-agent-client:examples:http-api:build
./gradlew :ati-sdk-agent-client:examples:mcp-client:build

# Run examples (requires target servers)
./gradlew :ati-sdk-agent-client:examples:http-api:run
./gradlew :ati-sdk-agent-client:examples:mcp-client:run

# Run with custom server URL
./gradlew :ati-sdk-agent-client:examples:http-api:run --args="https://your-agent.example.com:8443"
```

## Prerequisites

1. **ATI-registered agent** - An agent with HTTPS endpoint registered in the [ATI Console](https://dnsnext.console.aliyun.com/ati/agents)
2. **For DANE verification** - TLSA DNS records configured for the agent's hostname
3. **For Badge verification** - Agent registered in the ATI transparency log (CNNIC TL)
4. **For MCP example** - Client PKCS12 keystore containing identity certificate (see below)

## Verification Policies

All examples support different ATI verification policies:

| Policy | TLS | DANE | Badge | Description |
|--------|-----|------|-------|-------------|
| `PKI_ONLY` | ✓ | - | - | Standard HTTPS with system trust store |
| `BADGE_REQUIRED` | ✓ | - | ✓ | Requires transparency log verification (default) |
| `DANE_AND_BADGE` | ✓ | ✓ | ✓ | Requires both DANE and Badge |

## Integration Patterns

### Pattern 1: High-Level API (AtiClient)

The simplest approach using `AtiClient`:

```java
AtiClient client = AtiClient.builder()
    .connectTimeout(Duration.ofSeconds(10))
    .build();

AgentConnection conn = client.connect(
    "https://agent.example.com",
    ConnectOptions.builder()
        .verificationPolicy(VerificationPolicy.BADGE_REQUIRED)
        .transparencyClient(TransparencyClient.builder()
            .baseUrl(TransparencyClient.CNNIC_BASE_URL).build())
        .build());

HttpApiClient api = conn.httpApiAt(serverUrl);
String response = api.get("/health");
```

### Pattern 2: Low-Level Integration (AtiVerifiedClient with mTLS)

For SDKs that accept custom `SSLContext` (e.g., MCP SDK):

```java
// 1. Create AtiVerifiedClient with mTLS keystore
try (AtiVerifiedClient atiClient = AtiVerifiedClient.builder()
        .keyStorePath("/path/to/client.p12", "changeit")
        .transparencyClient(TransparencyClient.builder()
            .baseUrl(TransparencyClient.CNNIC_BASE_URL).build())
        .policy(VerificationPolicy.BADGE_REQUIRED)
        .build()) {

    // 2. Connect and pre-verify (DANE/Badge lookup)
    try (AtiConnection connection = atiClient.connect(serverUrl)) {

        // 3. Create your SDK client with ATI SSLContext
        HttpClientStreamableHttpTransport transport = HttpClientStreamableHttpTransport
            .builder(serverUrl)
            .customizeClient(b -> b.sslContext(atiClient.sslContext()))
            .build();

        // 4. Initialize your SDK client (triggers TLS handshake)
        McpSyncClient mcpClient = McpClient.sync(transport).build();
        mcpClient.initialize();

        // 5. Post-verify server certificate
        VerificationResult result = connection.verifyServer();
        if (!result.isSuccess()) {
            throw new SecurityException("ATI verification failed: " + result.reason());
        }

        // 6. Use verified connection
        var tools = mcpClient.listTools();
    }
}
```

## Creating a Client Keystore

For mTLS examples (mcp-client), you need a PKCS12 keystore containing your identity certificate:

```bash
# From PEM files (identity cert + private key):
openssl pkcs12 -export -in cert.pem -inkey key.pem -out client.p12 -name client -password pass:changeit

# Include CA chain if needed:
openssl pkcs12 -export -in cert.pem -inkey key.pem -certfile ca.pem -out client.p12 -name client
```

## Building from Source

These examples are Gradle subprojects. Build from the root:

```bash
./gradlew :ati-sdk-agent-client:examples:http-api:build
```

## Dependencies

| Example | Additional Dependencies |
|---------|------------------------|
| http-api | None (uses SDK only) |
| mcp-client | `io.modelcontextprotocol.sdk:mcp:1.1.2` |
