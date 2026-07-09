# ati-sdk-discovery

Agent discovery module — resolves agent information (host, version, badge URL) via DNS and Alibaba Cloud OpenAPI.

## Key Classes

- `DnsAtiDiscoveryClient` — DNS-based agent discovery client
- `AtiAgentDescriptor` — Resolved agent descriptor (host, version, endpoints)
- `AtiName` — ATI Name parser (`ati://v{version}.{agentHost}`)
- `AtiBadgeRecord` — Badge DNS record model
- `AtiDiscoveryRecord` — Discovery DNS record model

## Usage

```java
DnsAtiDiscoveryClient client = DnsAtiDiscoveryClient.builder()
    .endpoint("alidns.aliyuncs.com")
    .credentialsProvider(new AccessKeyCredentialsProvider(ak, sk))
    .build();

AtiAgentDescriptor agent = client.discover("agent.example.com", "1.0.0");
String badgeUrl = agent.getBadgeUrl();
```

## Dependencies

- `ati-sdk-core`
- Alibaba Cloud tea-openapi (OpenAPI client)
