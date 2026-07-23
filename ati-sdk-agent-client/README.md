# ati-sdk-agent-client

Agent client module — provides secure agent-to-agent connections with DANE TLSA verification, badge verification, and mTLS support.

## Key Classes

- `AtiVerifiedClient` — Main client for verified connections (Builder pattern)
- `ConnectOptions` — Connection options (verification policy, mTLS certs, auth headers)
- `VerificationPolicy` — Verification policies (BASIC, ENHANCED, ADVANCED for clients; NONE is server-only)
- `AtiConnection` — Established connection handle
- `HttpAuthHeadersProvider` — HTTP auth header injection (Bearer, API Key, custom)
- `AtiHttpClient` — Verifying HTTP client wrapper

## Usage

```java
AtiVerifiedClient client = AtiVerifiedClient.builder()
    .keyStorePath("/path/to/identity.p12", "password")
    .policy(VerificationPolicy.ENHANCED)
    .build();

AtiConnection conn = client.connect("https://agent.example.com",
    ConnectOptions.builder()
        .verificationPolicy(VerificationPolicy.ADVANCED)
        .clientCertPath(Path.of("/path/to/client.crt"), Path.of("/path/to/client.key"))
        .authProvider(HttpAuthHeadersProvider.bearer("token"))
        .build());
```

## Dependencies

- `ati-sdk-core`
- `ati-sdk-transparency`
- dnsjava 3.5.3 (DNS resolution)
- Caffeine 3.1.8 (caching)
