# ati-sdk-core

Core module providing configuration, authentication, HTTP client factory, and shared utilities for the ATI Java SDK.

## Key Classes

- `AtiConfiguration` — SDK configuration builder (environment, endpoint, timeouts)
- `Environment` — ATI environments (OTE, PRODUCTION)
- `AtiCredentials` — Credential container (access key ID + secret)
- `AtiCredentialsProvider` — Credential provider interface
- `HttpClientFactory` — Shared HTTP client factory
- `AtiExecutors` — Shared thread pool for async operations

## Usage

```java
AtiConfiguration config = AtiConfiguration.builder()
    .environment(Environment.OTE)
    .credentialsProvider(new AccessKeyCredentialsProvider(ak, sk))
    .build();
```

## Dependencies

- Jackson 2.16.1 (JSON serialization)
- SLF4J 2.0.9 (logging)
