# ati-sdk-spring-boot-starter

Spring Boot auto-configuration module — provides automatic bean registration for ATI SDK components based on `ati.sdk.*` properties.

## Key Classes

- `AtiSdkProperties` — Configuration properties (`ati.sdk.*` prefix)
- `AtiClientAutoConfiguration` — Client-side auto-configuration (discovery, connection)
- `AtiServerAutoConfiguration` — Server-side auto-configuration (mTLS, verification)

## Modes

Set `ati.sdk.mode` to configure which side to enable:

| Mode | Client Beans | Server Beans |
|------|-------------|-------------|
| `client` | Yes | No |
| `server` | No | Yes |
| `both` | Yes | Yes |

## Usage

```yaml
ati:
  sdk:
    mode: client
    identity:
      certificate: /path/to/identity.crt
      private-key: /path/to/identity.key
    transparency:
      base-url: https://ati-tl.cnnic.cn:8180
    verification:
      policy: ENHANCED
    client:
      dns-timeout: 5s
      connect-timeout: 10s
```

## Dependencies

- `ati-sdk-agent-client`
- `ati-sdk-discovery`
- Spring Boot 3.2.1
