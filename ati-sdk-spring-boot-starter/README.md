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
      base-url: https://ati-tl.cnnic.cn
      seal:
        # Optional; replaces the SDK-shipped Seal CA Chain used for Badge pre-verification.
        # A two-certificate (Root + Intermediate) PEM. Blank/unset uses the shipped chain.
        trust-certificate: /path/to/seal-ca-chain.pem
    verification:
      policy: ENHANCED
    client:
      dns-timeout: 5s
      connect-timeout: 10s
```

### Badge pre-verification trust (`ati.sdk.transparency.seal.trust-certificate`)

At Badge policies (`ENHANCED`/`ADVANCED`), both outbound **Connection** pre-verification (`AtiVerifiedClient` / `AtiClient`) and inbound **Client Verification** (`BadgeVerificationService`) path-validate each Badge Entry's Seal against a **Seal CA Chain** (ADR-0011). By default this is the SDK-shipped production chain; `ati.sdk.transparency.seal.trust-certificate` optionally replaces it with an operator-supplied Root + Intermediate PEM. A present-but-missing or malformed override fails closed at startup (`SealTrustChain` is not created). The Seal itself must carry `seal.certificate`; the legacy `publicKey`-only path is removed.

## Dependencies

- `ati-sdk-agent-client`
- `ati-sdk-discovery`
- Spring Boot 3.2.1
