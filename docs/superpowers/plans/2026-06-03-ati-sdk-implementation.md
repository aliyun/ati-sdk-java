# ATI SDK Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement ATI Java SDK modules for Agent discovery (DNS) and secure connection (mTLS + DANE/Badge verification).

**Architecture:** Four new Gradle modules built on top of existing `ati-sdk-core`. Discovery resolves `_ati` / `_ati-badge` DNS TXT records. Transparency queries TL API for Badge verification with seal + Merkle proof validation. Agent-client orchestrates DANE + Badge two-layer verification over mTLS. Spring Boot Starter auto-configures both client and server sides.

**Tech Stack:** Java 17, Gradle Kotlin DSL, dnsjava, Bouncy Castle, Caffeine, Jackson, Spring Boot Autoconfigure. Tests: JUnit 5 + AssertJ + Mockito.

**Spec:** `docs/superpowers/specs/2026-05-26-ati-sdk-design.md`

**Existing patterns (ati-sdk-core):** Final classes, Builder pattern with inner `Builder` class, `Objects.requireNonNull`, package-private test classes, AssertJ exclusively (no JUnit assertions), `assertThatThrownBy` for exceptions, `should*` test naming.

---

## File Structure

### ati-sdk-core (existing, add crypto package)

- `src/main/java/com/aliyun/ati/sdk/crypto/CertUtils.java` — SHA-256 fingerprint calculation
- `src/test/java/com/aliyun/ati/sdk/crypto/CertUtilsTest.java`

### ati-sdk-discovery (new module)

- `build.gradle.kts`
- `src/main/java/com/aliyun/ati/sdk/discovery/AtiName.java` — parse `ati://v{version}.{agentHost}`
- `src/main/java/com/aliyun/ati/sdk/discovery/AtiDiscoveryRecord.java` — parse `_ati` TXT record
- `src/main/java/com/aliyun/ati/sdk/discovery/AtiBadgeRecord.java` — parse `_ati-badge` TXT record
- `src/main/java/com/aliyun/ati/sdk/discovery/AtiAgentDescriptor.java` — agent info value object
- `src/main/java/com/aliyun/ati/sdk/discovery/AtiDiscoveryClient.java` — interface
- `src/main/java/com/aliyun/ati/sdk/discovery/DnsAtiDiscoveryClient.java` — dnsjava implementation
- `src/test/java/com/aliyun/ati/sdk/discovery/AtiNameTest.java`
- `src/test/java/com/aliyun/ati/sdk/discovery/AtiDiscoveryRecordTest.java`
- `src/test/java/com/aliyun/ati/sdk/discovery/AtiBadgeRecordTest.java`
- `src/test/java/com/aliyun/ati/sdk/discovery/DnsAtiDiscoveryClientTest.java`

### ati-sdk-transparency (new module)

- `build.gradle.kts`
- `src/main/java/com/aliyun/ati/sdk/transparency/model/TransparencyLogResponse.java`
- `src/main/java/com/aliyun/ati/sdk/transparency/model/TransparencyLogPayload.java`
- `src/main/java/com/aliyun/ati/sdk/transparency/model/Certificates.java`
- `src/main/java/com/aliyun/ati/sdk/transparency/model/Seal.java`
- `src/main/java/com/aliyun/ati/sdk/transparency/model/MerkleProof.java`
- `src/main/java/com/aliyun/ati/sdk/transparency/model/EvidenceRef.java`
- `src/main/java/com/aliyun/ati/sdk/transparency/AtiTransparencyClient.java`
- `src/main/java/com/aliyun/ati/sdk/transparency/RootKeyManager.java`
- `src/main/java/com/aliyun/ati/sdk/transparency/verification/TlSealVerifier.java`
- `src/main/java/com/aliyun/ati/sdk/transparency/verification/MerkleProofVerifier.java`
- `src/main/java/com/aliyun/ati/sdk/transparency/verification/VerificationStatus.java`
- `src/main/java/com/aliyun/ati/sdk/transparency/verification/ServerVerificationResult.java`
- `src/main/java/com/aliyun/ati/sdk/transparency/verification/ClientVerificationResult.java`
- `src/main/java/com/aliyun/ati/sdk/transparency/verification/BadgeVerificationService.java`
- `src/main/java/com/aliyun/ati/sdk/transparency/verification/CachingBadgeVerificationService.java`
- Tests mirror the source structure under `src/test/java/`

### ati-sdk-agent-client (new module)

- `build.gradle.kts`
- `src/main/java/com/aliyun/ati/sdk/agent/VerificationMode.java`
- `src/main/java/com/aliyun/ati/sdk/agent/VerificationPolicy.java`
- `src/main/java/com/aliyun/ati/sdk/agent/ConnectOptions.java`
- `src/main/java/com/aliyun/ati/sdk/agent/AtiConnection.java`
- `src/main/java/com/aliyun/ati/sdk/agent/AtiVerifiedClient.java`
- `src/main/java/com/aliyun/ati/sdk/agent/verification/DaneTlsaVerifier.java`
- `src/main/java/com/aliyun/ati/sdk/agent/verification/BadgeVerifier.java`
- `src/main/java/com/aliyun/ati/sdk/agent/verification/DefaultConnectionVerifier.java`
- `src/main/java/com/aliyun/ati/sdk/agent/verification/VerificationResult.java`
- `src/main/java/com/aliyun/ati/sdk/agent/http/CertificateCapturingTrustManager.java`
- `src/main/java/com/aliyun/ati/sdk/agent/http/AtiVerifiedSslContextFactory.java`
- `src/main/java/com/aliyun/ati/sdk/agent/server/ClientRequestVerifier.java`
- Tests mirror the source structure under `src/test/java/`

### ati-sdk-spring-boot-starter (new module)

- `build.gradle.kts`
- `src/main/java/com/aliyun/ati/sdk/spring/AtiSdkProperties.java`
- `src/main/java/com/aliyun/ati/sdk/spring/AtiClientAutoConfiguration.java`
- `src/main/java/com/aliyun/ati/sdk/spring/AtiServerAutoConfiguration.java`
- `src/main/resources/META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`
- `src/test/java/com/aliyun/ati/sdk/spring/AtiClientAutoConfigurationTest.java`
- `src/test/java/com/aliyun/ati/sdk/spring/AtiServerAutoConfigurationTest.java`

---

## Task 1: CertUtils — SHA-256 fingerprint calculation

**Files:**
- Create: `ati-sdk-core/src/main/java/com/aliyun/ati/sdk/crypto/CertUtils.java`
- Create: `ati-sdk-core/src/test/java/com/aliyun/ati/sdk/crypto/CertUtilsTest.java`

- [ ] **Step 1: Write the failing test**

```java
package com.aliyun.ati.sdk.crypto;

import java.security.cert.X509Certificate;
import javax.security.auth.x500.X500Principal;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class CertUtilsTest {

    @Test
    void shouldComputeSha256Fingerprint() throws Exception {
        byte[] encoded = "test-certificate-bytes".getBytes();
        X509Certificate cert = mock(X509Certificate.class);
        when(cert.getEncoded()).thenReturn(encoded);

        String fingerprint = CertUtils.sha256Fingerprint(cert);

        assertThat(fingerprint).matches("SHA-256:[a-f0-9]{64}");
    }

    @Test
    void shouldReturnConsistentFingerprintForSameInput() throws Exception {
        byte[] encoded = "same-bytes".getBytes();
        X509Certificate cert = mock(X509Certificate.class);
        when(cert.getEncoded()).thenReturn(encoded);

        String first = CertUtils.sha256Fingerprint(cert);
        String second = CertUtils.sha256Fingerprint(cert);

        assertThat(first).isEqualTo(second);
    }

    @Test
    void shouldComputeFingerprintFromRawBytes() {
        byte[] data = "test-data".getBytes();

        String fingerprint = CertUtils.sha256Hex(data);

        assertThat(fingerprint).hasSize(64).matches("[a-f0-9]{64}");
    }

    @Test
    void shouldCompareFingerprrintsInConstantTime() throws Exception {
        String a = "SHA-256:abcd1234";
        String b = "SHA-256:abcd1234";
        String c = "SHA-256:different";

        assertThat(CertUtils.fingerprintMatches(a, b)).isTrue();
        assertThat(CertUtils.fingerprintMatches(a, c)).isFalse();
    }

    @Test
    void shouldRejectNullCertificate() {
        assertThatThrownBy(() -> CertUtils.sha256Fingerprint(null))
            .isInstanceOf(NullPointerException.class);
    }
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `gradle :ati-sdk-core:test --tests "com.aliyun.ati.sdk.crypto.CertUtilsTest" --info`
Expected: Compilation failure — `CertUtils` class does not exist.

- [ ] **Step 3: Implement CertUtils**

```java
package com.aliyun.ati.sdk.crypto;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Objects;

public final class CertUtils {

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private CertUtils() { }

    public static String sha256Fingerprint(X509Certificate cert) {
        Objects.requireNonNull(cert, "Certificate must not be null");
        try {
            return "SHA-256:" + sha256Hex(cert.getEncoded());
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException("Failed to encode certificate", e);
        }
    }

    public static String sha256Hex(byte[] data) {
        Objects.requireNonNull(data, "Data must not be null");
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data);
            return bytesToHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    public static boolean fingerprintMatches(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        return MessageDigest.isEqual(a.getBytes(), b.getBytes());
    }

    private static String bytesToHex(byte[] bytes) {
        char[] hex = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            hex[i * 2] = HEX[(bytes[i] >> 4) & 0x0F];
            hex[i * 2 + 1] = HEX[bytes[i] & 0x0F];
        }
        return new String(hex);
    }
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `gradle :ati-sdk-core:test --tests "com.aliyun.ati.sdk.crypto.CertUtilsTest" --info`
Expected: All 5 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add ati-sdk-core/src/main/java/com/aliyun/ati/sdk/crypto/CertUtils.java \
       ati-sdk-core/src/test/java/com/aliyun/ati/sdk/crypto/CertUtilsTest.java
git commit -m "feat(core): add CertUtils for SHA-256 fingerprint calculation"
```

---

## Task 2: Discovery module setup + AtiName

**Files:**
- Create: `ati-sdk-discovery/build.gradle.kts`
- Modify: `settings.gradle.kts` — add `include("ati-sdk-discovery")`
- Modify: `gradle.properties` — add `dnsjavaVersion=3.5.3`
- Create: `ati-sdk-discovery/src/main/java/com/aliyun/ati/sdk/discovery/AtiName.java`
- Create: `ati-sdk-discovery/src/test/java/com/aliyun/ati/sdk/discovery/AtiNameTest.java`

- [ ] **Step 1: Create module build file and register in settings**

`ati-sdk-discovery/build.gradle.kts`:
```kotlin
val dnsjavaVersion by project

dependencies {
    api(project(":ati-sdk-core"))
    implementation("dnsjava:dnsjava:$dnsjavaVersion")

    testImplementation("org.junit.jupiter:junit-jupiter:${project.property("junitVersion")}")
    testImplementation("org.mockito:mockito-core:${project.property("mockitoVersion")}")
    testImplementation("org.assertj:assertj-core:${project.property("assertjVersion")}")
    testRuntimeOnly("org.slf4j:slf4j-simple:${project.property("slf4jVersion")}")
}
```

Add to `settings.gradle.kts`:
```kotlin
include("ati-sdk-discovery")
```

Add to `gradle.properties`:
```properties
dnsjavaVersion=3.5.3
```

- [ ] **Step 2: Write AtiName failing test**

```java
package com.aliyun.ati.sdk.discovery;

import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AtiNameTest {

    @Test
    void shouldParseValidAtiName() {
        AtiName name = AtiName.parse("ati://v1.my-agent.example.com");

        assertThat(name.getVersion()).isEqualTo("1");
        assertThat(name.getAgentHost()).isEqualTo("my-agent.example.com");
    }

    @Test
    void shouldParseSemanticVersion() {
        AtiName name = AtiName.parse("ati://v1.2.3.agent.example.com");

        assertThat(name.getVersion()).isEqualTo("1.2.3");
        assertThat(name.getAgentHost()).isEqualTo("agent.example.com");
    }

    @Test
    void shouldReturnOriginalUri() {
        String uri = "ati://v1.my-agent.example.com";
        AtiName name = AtiName.parse(uri);

        assertThat(name.toUri()).isEqualTo(uri);
    }

    @Test
    void shouldRejectNullInput() {
        assertThatThrownBy(() -> AtiName.parse(null))
            .isInstanceOf(NullPointerException.class);
    }

    @Test
    void shouldRejectInvalidScheme() {
        assertThatThrownBy(() -> AtiName.parse("http://v1.example.com"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("ati://");
    }

    @Test
    void shouldRejectMissingVersion() {
        assertThatThrownBy(() -> AtiName.parse("ati://example.com"))
            .isInstanceOf(IllegalArgumentException.class);
    }

    @Test
    void shouldImplementEqualsAndHashCode() {
        AtiName a = AtiName.parse("ati://v1.agent.example.com");
        AtiName b = AtiName.parse("ati://v1.agent.example.com");

        assertThat(a).isEqualTo(b);
        assertThat(a.hashCode()).isEqualTo(b.hashCode());
    }
}
```

- [ ] **Step 3: Implement AtiName**

```java
package com.aliyun.ati.sdk.discovery;

import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class AtiName {

    private static final String SCHEME = "ati://";
    // matches: v{version-segments}.{host with at least 2 parts}
    private static final Pattern PATTERN =
        Pattern.compile("^ati://v([0-9]+(?:\\.[0-9]+)*)\\.([a-zA-Z0-9][-a-zA-Z0-9]*(?:\\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)$");

    private final String version;
    private final String agentHost;

    private AtiName(String version, String agentHost) {
        this.version = version;
        this.agentHost = agentHost;
    }

    public static AtiName parse(String uri) {
        Objects.requireNonNull(uri, "ATI name URI must not be null");
        Matcher matcher = PATTERN.matcher(uri);
        if (!matcher.matches()) {
            throw new IllegalArgumentException(
                "Invalid ATI name: '" + uri + "'. Expected format: ati://v{version}.{agentHost}");
        }
        return new AtiName(matcher.group(1), matcher.group(2));
    }

    public String getVersion() { return version; }

    public String getAgentHost() { return agentHost; }

    public String toUri() { return SCHEME + "v" + version + "." + agentHost; }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof AtiName other)) return false;
        return version.equals(other.version) && agentHost.equals(other.agentHost);
    }

    @Override
    public int hashCode() { return Objects.hash(version, agentHost); }

    @Override
    public String toString() { return toUri(); }
}
```

- [ ] **Step 4: Run tests**

Run: `gradle :ati-sdk-discovery:test --tests "com.aliyun.ati.sdk.discovery.AtiNameTest" --info`
Expected: All 7 tests PASS.

- [ ] **Step 5: Commit**

```bash
git add ati-sdk-discovery/ settings.gradle.kts gradle.properties
git commit -m "feat(discovery): add ati-sdk-discovery module with AtiName parser"
```

---

## Task 3: DNS record parsing — AtiDiscoveryRecord + AtiBadgeRecord

**Files:**
- Create: `ati-sdk-discovery/src/main/java/com/aliyun/ati/sdk/discovery/AtiDiscoveryRecord.java`
- Create: `ati-sdk-discovery/src/main/java/com/aliyun/ati/sdk/discovery/AtiBadgeRecord.java`
- Create: `ati-sdk-discovery/src/test/java/com/aliyun/ati/sdk/discovery/AtiDiscoveryRecordTest.java`
- Create: `ati-sdk-discovery/src/test/java/com/aliyun/ati/sdk/discovery/AtiBadgeRecordTest.java`

- [ ] **Step 1: Write AtiDiscoveryRecord test**

```java
package com.aliyun.ati.sdk.discovery;

import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AtiDiscoveryRecordTest {

    @Test
    void shouldParseFullRecord() {
        String txt = "v=ati1; version=v1.0.0; url=https://agent.example.com/.well-known/ati/trust-card.json";
        AtiDiscoveryRecord record = AtiDiscoveryRecord.parse(txt);

        assertThat(record.getFormatVersion()).isEqualTo("ati1");
        assertThat(record.getVersion()).isEqualTo("v1.0.0");
        assertThat(record.getUrl()).isEqualTo("https://agent.example.com/.well-known/ati/trust-card.json");
        assertThat(record.getMode()).isEqualTo("card");
    }

    @Test
    void shouldParseDirectMode() {
        String txt = "v=ati1; version=v2.0.0; mode=direct";
        AtiDiscoveryRecord record = AtiDiscoveryRecord.parse(txt);

        assertThat(record.getMode()).isEqualTo("direct");
        assertThat(record.getUrl()).isNull();
    }

    @Test
    void shouldRejectInvalidFormatVersion() {
        assertThatThrownBy(() -> AtiDiscoveryRecord.parse("v=ans1; version=v1.0.0"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("ati1");
    }

    @Test
    void shouldRejectMissingVersion() {
        assertThatThrownBy(() -> AtiDiscoveryRecord.parse("v=ati1"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("version");
    }
}
```

- [ ] **Step 2: Implement AtiDiscoveryRecord**

Parse `v=ati1; version=v1.0.0; url=...; mode=card` format using semicolon-delimited key=value pairs. Fields: `formatVersion`, `version`, `url` (nullable), `mode` (defaults to `"card"`). Validate `v=ati1` and `version` is present.

```java
package com.aliyun.ati.sdk.discovery;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

public final class AtiDiscoveryRecord {

    private final String formatVersion;
    private final String version;
    private final String url;
    private final String mode;

    private AtiDiscoveryRecord(String formatVersion, String version, String url, String mode) {
        this.formatVersion = formatVersion;
        this.version = version;
        this.url = url;
        this.mode = mode;
    }

    public static AtiDiscoveryRecord parse(String txt) {
        Objects.requireNonNull(txt, "TXT record must not be null");
        Map<String, String> fields = parseFields(txt);

        String v = fields.get("v");
        if (!"ati1".equals(v)) {
            throw new IllegalArgumentException("Expected v=ati1, got: " + v);
        }
        String version = fields.get("version");
        if (version == null || version.isBlank()) {
            throw new IllegalArgumentException("Missing required field: version");
        }
        String mode = fields.getOrDefault("mode", "card");
        String url = fields.get("url");
        return new AtiDiscoveryRecord(v, version, url, mode);
    }

    private static Map<String, String> parseFields(String txt) {
        Map<String, String> map = new HashMap<>();
        for (String part : txt.split(";")) {
            String trimmed = part.trim();
            int eq = trimmed.indexOf('=');
            if (eq > 0) {
                map.put(trimmed.substring(0, eq).trim(), trimmed.substring(eq + 1).trim());
            }
        }
        return map;
    }

    public String getFormatVersion() { return formatVersion; }
    public String getVersion() { return version; }
    public String getUrl() { return url; }
    public String getMode() { return mode; }
}
```

- [ ] **Step 3: Write AtiBadgeRecord test**

```java
package com.aliyun.ati.sdk.discovery;

import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class AtiBadgeRecordTest {

    @Test
    void shouldParseValidBadgeRecord() {
        String txt = "v=ati-badge1; version=v1.0.0; url=https://tl.ansagent.cn:8180/tl/agents/abc-123-def";
        AtiBadgeRecord record = AtiBadgeRecord.parse(txt);

        assertThat(record.getFormatVersion()).isEqualTo("ati-badge1");
        assertThat(record.getVersion()).isEqualTo("v1.0.0");
        assertThat(record.getUrl()).isEqualTo("https://tl.ansagent.cn:8180/tl/agents/abc-123-def");
        assertThat(record.getAgentId()).isEqualTo("abc-123-def");
    }

    @Test
    void shouldExtractUuidAgentId() {
        String txt = "v=ati-badge1; version=v1.0.0; url=https://tl.ansagent.cn:8180/tl/agents/28b8f491-f110-4705-b8b9-dc8e91d452e0";
        AtiBadgeRecord record = AtiBadgeRecord.parse(txt);

        assertThat(record.getAgentId()).isEqualTo("28b8f491-f110-4705-b8b9-dc8e91d452e0");
    }

    @Test
    void shouldRejectInvalidFormatVersion() {
        assertThatThrownBy(() -> AtiBadgeRecord.parse("v=ans-badge1; version=v1.0.0; url=https://tl/agents/x"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("ati-badge1");
    }

    @Test
    void shouldRejectMissingUrl() {
        assertThatThrownBy(() -> AtiBadgeRecord.parse("v=ati-badge1; version=v1.0.0"))
            .isInstanceOf(IllegalArgumentException.class)
            .hasMessageContaining("url");
    }
}
```

- [ ] **Step 4: Implement AtiBadgeRecord**

Parse `v=ati-badge1; version=v1.0.0; url=https://tl.ansagent.cn:8180/tl/agents/{agentId}`. Extract `agentId` from URL path segment after `/tl/agents/`.

```java
package com.aliyun.ati.sdk.discovery;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public final class AtiBadgeRecord {

    private static final Pattern AGENT_ID_PATTERN = Pattern.compile("/tl/agents/([^/]+)/?$");

    private final String formatVersion;
    private final String version;
    private final String url;
    private final String agentId;

    private AtiBadgeRecord(String formatVersion, String version, String url, String agentId) {
        this.formatVersion = formatVersion;
        this.version = version;
        this.url = url;
        this.agentId = agentId;
    }

    public static AtiBadgeRecord parse(String txt) {
        Objects.requireNonNull(txt, "TXT record must not be null");
        Map<String, String> fields = parseFields(txt);

        String v = fields.get("v");
        if (!"ati-badge1".equals(v)) {
            throw new IllegalArgumentException("Expected v=ati-badge1, got: " + v);
        }
        String version = fields.get("version");
        if (version == null || version.isBlank()) {
            throw new IllegalArgumentException("Missing required field: version");
        }
        String url = fields.get("url");
        if (url == null || url.isBlank()) {
            throw new IllegalArgumentException("Missing required field: url");
        }
        String agentId = extractAgentId(url);
        return new AtiBadgeRecord(v, version, url, agentId);
    }

    private static String extractAgentId(String url) {
        Matcher matcher = AGENT_ID_PATTERN.matcher(url);
        if (!matcher.find()) {
            throw new IllegalArgumentException("Cannot extract agentId from URL: " + url);
        }
        return matcher.group(1);
    }

    private static Map<String, String> parseFields(String txt) {
        Map<String, String> map = new HashMap<>();
        for (String part : txt.split(";")) {
            String trimmed = part.trim();
            int eq = trimmed.indexOf('=');
            if (eq > 0) {
                map.put(trimmed.substring(0, eq).trim(), trimmed.substring(eq + 1).trim());
            }
        }
        return map;
    }

    public String getFormatVersion() { return formatVersion; }
    public String getVersion() { return version; }
    public String getUrl() { return url; }
    public String getAgentId() { return agentId; }
}
```

- [ ] **Step 5: Run tests and commit**

Run: `gradle :ati-sdk-discovery:test --info`
Expected: All tests PASS.

```bash
git add ati-sdk-discovery/src/
git commit -m "feat(discovery): add AtiDiscoveryRecord and AtiBadgeRecord TXT parsers"
```

---

## Task 4: AtiAgentDescriptor + AtiDiscoveryClient

**Files:**
- Create: `ati-sdk-discovery/src/main/java/com/aliyun/ati/sdk/discovery/AtiAgentDescriptor.java`
- Create: `ati-sdk-discovery/src/main/java/com/aliyun/ati/sdk/discovery/AtiDiscoveryClient.java`
- Create: `ati-sdk-discovery/src/main/java/com/aliyun/ati/sdk/discovery/DnsAtiDiscoveryClient.java`
- Create: `ati-sdk-discovery/src/test/java/com/aliyun/ati/sdk/discovery/AtiAgentDescriptorTest.java`
- Create: `ati-sdk-discovery/src/test/java/com/aliyun/ati/sdk/discovery/DnsAtiDiscoveryClientTest.java`

- [ ] **Step 1: Implement AtiAgentDescriptor (simple value object, test inline)**

```java
package com.aliyun.ati.sdk.discovery;

import java.util.Objects;

public final class AtiAgentDescriptor {

    private final String agentHost;
    private final String version;
    private final String badgeUrl;
    private final String agentId;

    public AtiAgentDescriptor(String agentHost, String version, String badgeUrl, String agentId) {
        this.agentHost = Objects.requireNonNull(agentHost, "agentHost must not be null");
        this.version = Objects.requireNonNull(version, "version must not be null");
        this.badgeUrl = badgeUrl;
        this.agentId = agentId;
    }

    public String getAgentHost() { return agentHost; }
    public String getVersion() { return version; }
    public String getBadgeUrl() { return badgeUrl; }
    public String getAgentId() { return agentId; }

    @Override
    public String toString() {
        return "AtiAgentDescriptor{host=" + agentHost + ", version=" + version + ", agentId=" + agentId + "}";
    }
}
```

- [ ] **Step 2: Implement AtiDiscoveryClient interface**

```java
package com.aliyun.ati.sdk.discovery;

public interface AtiDiscoveryClient {
    AtiAgentDescriptor discover(AtiName name);
}
```

- [ ] **Step 3: Implement DnsAtiDiscoveryClient**

```java
package com.aliyun.ati.sdk.discovery;

import java.time.Duration;
import java.util.Objects;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Record;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.Type;

public final class DnsAtiDiscoveryClient implements AtiDiscoveryClient {

    private static final Logger LOG = LoggerFactory.getLogger(DnsAtiDiscoveryClient.class);
    private static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(5);

    private final Duration timeout;

    public DnsAtiDiscoveryClient() {
        this(DEFAULT_TIMEOUT);
    }

    public DnsAtiDiscoveryClient(Duration timeout) {
        this.timeout = Objects.requireNonNull(timeout, "timeout must not be null");
    }

    @Override
    public AtiAgentDescriptor discover(AtiName name) {
        Objects.requireNonNull(name, "AtiName must not be null");
        String host = name.getAgentHost();
        String version = name.getVersion();

        String badgeUrl = null;
        String agentId = null;

        String badgeTxt = lookupTxt("_ati-badge." + host);
        if (badgeTxt != null) {
            AtiBadgeRecord badge = AtiBadgeRecord.parse(badgeTxt);
            badgeUrl = badge.getUrl();
            agentId = badge.getAgentId();
        }

        return new AtiAgentDescriptor(host, version, badgeUrl, agentId);
    }

    private String lookupTxt(String name) {
        try {
            Lookup lookup = new Lookup(name, Type.TXT);
            SimpleResolver resolver = new SimpleResolver();
            resolver.setTimeout(timeout);
            lookup.setResolver(resolver);
            Record[] records = lookup.run();
            if (records == null || records.length == 0) {
                LOG.debug("No TXT record found for {}", name);
                return null;
            }
            TXTRecord txt = (TXTRecord) records[0];
            return String.join("", txt.getStrings());
        } catch (Exception e) {
            LOG.warn("DNS lookup failed for {}: {}", name, e.getMessage());
            return null;
        }
    }
}
```

- [ ] **Step 4: Write DnsAtiDiscoveryClient test (mock-based unit test)**

```java
package com.aliyun.ati.sdk.discovery;

import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class DnsAtiDiscoveryClientTest {

    @Test
    void shouldRejectNullAtiName() {
        DnsAtiDiscoveryClient client = new DnsAtiDiscoveryClient();
        assertThatThrownBy(() -> client.discover(null))
            .isInstanceOf(NullPointerException.class);
    }

    @Test
    void shouldReturnDescriptorWithNullBadgeWhenDnsUnavailable() {
        DnsAtiDiscoveryClient client = new DnsAtiDiscoveryClient();
        AtiName name = AtiName.parse("ati://v1.nonexistent.invalid");

        AtiAgentDescriptor descriptor = client.discover(name);

        assertThat(descriptor.getAgentHost()).isEqualTo("nonexistent.invalid");
        assertThat(descriptor.getVersion()).isEqualTo("1");
        assertThat(descriptor.getBadgeUrl()).isNull();
        assertThat(descriptor.getAgentId()).isNull();
    }
}
```

- [ ] **Step 5: Run tests and commit**

Run: `gradle :ati-sdk-discovery:test --info`
Expected: All tests PASS.

```bash
git add ati-sdk-discovery/src/
git commit -m "feat(discovery): add AtiAgentDescriptor, AtiDiscoveryClient, DnsAtiDiscoveryClient"
```

---

## Task 5: Transparency module setup + TL response models

**Files:**
- Create: `ati-sdk-transparency/build.gradle.kts`
- Modify: `settings.gradle.kts` — add `include("ati-sdk-transparency")`
- Modify: `gradle.properties` — add Bouncy Castle + Caffeine versions
- Create: all model classes under `com.aliyun.ati.sdk.transparency.model`

- [ ] **Step 1: Create module build file and register**

`ati-sdk-transparency/build.gradle.kts`:
```kotlin
val bouncyCastleVersion by project
val caffeineVersion by project

dependencies {
    api(project(":ati-sdk-core"))
    implementation("org.bouncycastle:bcprov-jdk18on:$bouncyCastleVersion")
    implementation("com.github.ben-manes.caffeine:caffeine:$caffeineVersion")
    implementation("com.fasterxml.jackson.core:jackson-databind:${project.property("jacksonVersion")}")
    implementation("com.fasterxml.jackson.datatype:jackson-datatype-jsr310:${project.property("jacksonVersion")}")

    testImplementation("org.junit.jupiter:junit-jupiter:${project.property("junitVersion")}")
    testImplementation("org.mockito:mockito-core:${project.property("mockitoVersion")}")
    testImplementation("org.assertj:assertj-core:${project.property("assertjVersion")}")
    testRuntimeOnly("org.slf4j:slf4j-simple:${project.property("slf4jVersion")}")
}
```

Add to `settings.gradle.kts`: `include("ati-sdk-transparency")`

Add to `gradle.properties`:
```properties
bouncyCastleVersion=1.77
caffeineVersion=3.1.8
```

- [ ] **Step 2: Create TL response models**

These are Jackson-annotated POJOs matching the ATI TL API response format. All classes use `@JsonIgnoreProperties(ignoreUnknown = true)`.

`TransparencyLogResponse.java` — top-level: `status`, `schemaVersion`, `payload` (TransparencyLogPayload), `evidenceRef` (EvidenceRef), `seal` (Seal), `merkleProof` (MerkleProof).

`TransparencyLogPayload.java` — `logId`, `eventType`, `timestamp`, `agentName`, `agentHost`, `version`, `agentId`, `agentStatus`, `certificates` (Certificates).

`Certificates.java` — `serverCertFingerprint`, `identityCertFingerprint`.

`Seal.java` — `canonicalization`, `digestAlgorithm`, `signatureAlgorithm`, `signatureEncoding`, `keyId`, `signature`, `publicKey`.

`MerkleProof.java` — `leafHash`, `leafIndex` (long), `treeSize` (long), `treeVersion` (long), `path` (List<String>), `rootHash`.

`EvidenceRef.java` — `evidenceId`, `submitterId`, `evidenceType`, `evidenceUri`, `evidenceHash`, remaining fields.

All models: final class, private no-arg constructor for Jackson, getters only.

- [ ] **Step 3: Write model deserialization test**

Test that Jackson can parse the full TL response JSON from the spec into `TransparencyLogResponse`. Use the exact JSON example from the ATI TL API spec.

- [ ] **Step 4: Run tests and commit**

Run: `gradle :ati-sdk-transparency:test --info`
Expected: All tests PASS.

```bash
git add ati-sdk-transparency/ settings.gradle.kts gradle.properties
git commit -m "feat(transparency): add ati-sdk-transparency module with TL response models"
```

---

## Task 6: AtiTransparencyClient

**Files:**
- Create: `ati-sdk-transparency/src/main/java/com/aliyun/ati/sdk/transparency/AtiTransparencyClient.java`
- Create: `ati-sdk-transparency/src/test/java/com/aliyun/ati/sdk/transparency/AtiTransparencyClientTest.java`

- [ ] **Step 1: Implement AtiTransparencyClient**

Uses `java.net.http.HttpClient` (same pattern as `HttpClientFactory` in core). Two methods:
- `getLatestLog(String agentId)` → `GET /tl/agents/{agentId}/logs/latest` → returns `TransparencyLogResponse`
- `getRootKeys()` → `GET /tl/root-keys` → returns raw `String` response

Constructor takes `baseUrl` (String) and `HttpClient`. Uses Jackson `ObjectMapper` for JSON deserialization. Throws `AtiServerException` for non-200 responses, `AtiNotFoundException` for 404.

- [ ] **Step 2: Write test with Mockito mock of HttpClient**

Mock `HttpClient.send()` to return a canned JSON response. Verify deserialization works end-to-end. Test 404 → `AtiNotFoundException`. Test 500 → `AtiServerException`.

- [ ] **Step 3: Run tests and commit**

Run: `gradle :ati-sdk-transparency:test --info`

```bash
git add ati-sdk-transparency/src/
git commit -m "feat(transparency): add AtiTransparencyClient for TL API calls"
```

---

## Task 7: RootKeyManager

**Files:**
- Create: `ati-sdk-transparency/src/main/java/com/aliyun/ati/sdk/transparency/RootKeyManager.java`
- Create: `ati-sdk-transparency/src/test/java/com/aliyun/ati/sdk/transparency/RootKeyManagerTest.java`

- [ ] **Step 1: Implement RootKeyManager**

Wraps `AtiTransparencyClient.getRootKeys()` with Caffeine cache (24h TTL). Parses the PEM public key response into `java.security.PublicKey`. Caches as `Map<String, PublicKey>` keyed by `keyId`.

Initial implementation: assume `GET /tl/root-keys` returns a single PEM public key. The `keyId` mapping can be confirmed once the TL endpoint format is finalized.

- [ ] **Step 2: Write test**

Mock `AtiTransparencyClient`, verify caching behavior (second call returns cached result without calling TL again). Verify PEM parsing produces a valid EC `PublicKey`.

- [ ] **Step 3: Run tests and commit**

```bash
git add ati-sdk-transparency/src/
git commit -m "feat(transparency): add RootKeyManager with 24h cache"
```

---

## Task 8: TlSealVerifier

**Files:**
- Create: `ati-sdk-transparency/src/main/java/com/aliyun/ati/sdk/transparency/verification/TlSealVerifier.java`
- Create: `ati-sdk-transparency/src/test/java/com/aliyun/ati/sdk/transparency/verification/TlSealVerifierTest.java`

- [ ] **Step 1: Implement TlSealVerifier**

Verifies `Seal` from TL response:
1. JCS-canonicalize the content (status + schemaVersion + payload + evidenceRef) using Jackson with sorted keys
2. SHA-256 hash the canonical JSON
3. Verify ECDSA signature using `Seal.signature` (DER base64) against the hash with the TL public key from `RootKeyManager`

Method: `boolean verify(TransparencyLogResponse response, PublicKey tlPublicKey)`

Uses `java.security.Signature` with `SHA256withECDSA`.

- [ ] **Step 2: Write test**

Generate an EC key pair in the test. Sign a known canonical JSON with the private key. Verify that `TlSealVerifier` accepts the valid signature and rejects a tampered one.

- [ ] **Step 3: Run tests and commit**

```bash
git add ati-sdk-transparency/src/
git commit -m "feat(transparency): add TlSealVerifier for seal signature verification"
```

---

## Task 9: MerkleProofVerifier

**Files:**
- Create: `ati-sdk-transparency/src/main/java/com/aliyun/ati/sdk/transparency/verification/MerkleProofVerifier.java`
- Create: `ati-sdk-transparency/src/test/java/com/aliyun/ati/sdk/transparency/verification/MerkleProofVerifierTest.java`

- [ ] **Step 1: Implement MerkleProofVerifier**

RFC 9162 Merkle inclusion proof verification:
- `LEAF_PREFIX = 0x00`, `NODE_PREFIX = 0x01`
- `hashLeaf(data)` = `SHA-256(0x00 || data)`
- `hashNode(left, right)` = `SHA-256(0x01 || left || right)`
- `verifyInclusion(leafData, leafIndex, treeSize, path, expectedRootHash)` — walks the path from leaf to root, compares computed root with expected root using `MessageDigest.isEqual()` (constant time).

Method: `boolean verify(MerkleProof proof, byte[] leafData)`

- [ ] **Step 2: Write test**

Test cases: single-element tree (empty path), two-element tree, four-element balanced tree, wrong root hash → false, path too long → false.

- [ ] **Step 3: Run tests and commit**

```bash
git add ati-sdk-transparency/src/
git commit -m "feat(transparency): add MerkleProofVerifier (RFC 9162)"
```

---

## Task 10: BadgeVerificationService + result types

**Files:**
- Create: `ati-sdk-transparency/src/main/java/com/aliyun/ati/sdk/transparency/verification/VerificationStatus.java`
- Create: `ati-sdk-transparency/src/main/java/com/aliyun/ati/sdk/transparency/verification/ServerVerificationResult.java`
- Create: `ati-sdk-transparency/src/main/java/com/aliyun/ati/sdk/transparency/verification/ClientVerificationResult.java`
- Create: `ati-sdk-transparency/src/main/java/com/aliyun/ati/sdk/transparency/verification/BadgeVerificationService.java`
- Create tests

- [ ] **Step 1: Implement VerificationStatus enum**

```java
package com.aliyun.ati.sdk.transparency.verification;

public enum VerificationStatus {
    VERIFIED,
    NOT_ATI_AGENT,
    REGISTRATION_INVALID,
    FINGERPRINT_MISMATCH,
    SEAL_INVALID,
    MERKLE_PROOF_INVALID,
    AGENT_REVOKED,
    LOOKUP_FAILED
}
```

- [ ] **Step 2: Implement ServerVerificationResult and ClientVerificationResult**

`ServerVerificationResult`: `status` (VerificationStatus), `serverCertFingerprint` (String), `agentId` (String).

`ClientVerificationResult`: `status` (VerificationStatus), `identityCertFingerprint` (String), `agentHost` (String), `agentId` (String).

Both are immutable value objects.

- [ ] **Step 3: Implement BadgeVerificationService**

Constructor takes `AtiTransparencyClient`, `RootKeyManager`, `TlSealVerifier`, `MerkleProofVerifier`.

`verifyServer(String agentId)`:
1. Call `AtiTransparencyClient.getLatestLog(agentId)` → `TransparencyLogResponse`
2. Check `status == "ACTIVE"`, else return `AGENT_REVOKED`
3. Get TL public key from `RootKeyManager`
4. Verify seal with `TlSealVerifier` → if fail, `SEAL_INVALID`
5. Verify Merkle proof with `MerkleProofVerifier` → if fail, `MERKLE_PROOF_INVALID`
6. Return `VERIFIED` with `serverCertFingerprint` from payload

`verifyClient(String agentId)`:
Same flow but returns `ClientVerificationResult` with `identityCertFingerprint`.

- [ ] **Step 4: Write test with Mockito**

Mock all dependencies. Test happy path → VERIFIED. Test revoked agent → AGENT_REVOKED. Test bad seal → SEAL_INVALID. Test TL 404 → NOT_ATI_AGENT.

- [ ] **Step 5: Run tests and commit**

```bash
git add ati-sdk-transparency/src/
git commit -m "feat(transparency): add BadgeVerificationService with seal + Merkle verification"
```

---

## Task 11: CachingBadgeVerificationService

**Files:**
- Create: `ati-sdk-transparency/src/main/java/com/aliyun/ati/sdk/transparency/verification/CachingBadgeVerificationService.java`
- Create: `ati-sdk-transparency/src/test/java/com/aliyun/ati/sdk/transparency/verification/CachingBadgeVerificationServiceTest.java`

- [ ] **Step 1: Implement CachingBadgeVerificationService**

Wraps `BadgeVerificationService` with Caffeine cache. Positive results (VERIFIED): 15min TTL. Negative results: 5min TTL. Max 10,000 entries. Cache key: `agentId` for server verification, cert SHA-256 fingerprint for client verification.

- [ ] **Step 2: Write test**

Verify second call returns cached result. Verify cache key is agentId.

- [ ] **Step 3: Run tests and commit**

```bash
git add ati-sdk-transparency/src/
git commit -m "feat(transparency): add CachingBadgeVerificationService with Caffeine"
```

---

## Task 12: Agent-client module setup + VerificationMode + VerificationPolicy

**Files:**
- Create: `ati-sdk-agent-client/build.gradle.kts`
- Modify: `settings.gradle.kts` — add `include("ati-sdk-agent-client")`
- Create: `ati-sdk-agent-client/src/main/java/com/aliyun/ati/sdk/agent/VerificationMode.java`
- Create: `ati-sdk-agent-client/src/main/java/com/aliyun/ati/sdk/agent/VerificationPolicy.java`
- Create tests

- [ ] **Step 1: Create module build file**

```kotlin
dependencies {
    api(project(":ati-sdk-core"))
    api(project(":ati-sdk-discovery"))
    api(project(":ati-sdk-transparency"))
    implementation("dnsjava:dnsjava:${project.property("dnsjavaVersion")}")

    testImplementation("org.junit.jupiter:junit-jupiter:${project.property("junitVersion")}")
    testImplementation("org.mockito:mockito-core:${project.property("mockitoVersion")}")
    testImplementation("org.assertj:assertj-core:${project.property("assertjVersion")}")
    testRuntimeOnly("org.slf4j:slf4j-simple:${project.property("slf4jVersion")}")
}
```

- [ ] **Step 2: Implement VerificationMode enum**

```java
package com.aliyun.ati.sdk.agent;

public enum VerificationMode {
    DISABLED,
    ADVISORY,
    REQUIRED
}
```

- [ ] **Step 3: Implement VerificationPolicy**

```java
package com.aliyun.ati.sdk.agent;

public final class VerificationPolicy {

    public static final VerificationPolicy PKI_ONLY =
        new VerificationPolicy("PKI_ONLY", VerificationMode.DISABLED, VerificationMode.DISABLED);
    public static final VerificationPolicy BADGE_REQUIRED =
        new VerificationPolicy("BADGE_REQUIRED", VerificationMode.DISABLED, VerificationMode.REQUIRED);
    public static final VerificationPolicy DANE_REQUIRED =
        new VerificationPolicy("DANE_REQUIRED", VerificationMode.REQUIRED, VerificationMode.DISABLED);
    public static final VerificationPolicy DANE_AND_BADGE =
        new VerificationPolicy("DANE_AND_BADGE", VerificationMode.REQUIRED, VerificationMode.REQUIRED);

    private final String name;
    private final VerificationMode daneMode;
    private final VerificationMode badgeMode;

    public VerificationPolicy(String name, VerificationMode daneMode, VerificationMode badgeMode) {
        this.name = name;
        this.daneMode = daneMode;
        this.badgeMode = badgeMode;
    }

    public String getName() { return name; }
    public VerificationMode getDaneMode() { return daneMode; }
    public VerificationMode getBadgeMode() { return badgeMode; }

    @Override
    public String toString() { return name; }
}
```

- [ ] **Step 4: Write tests and commit**

Test that predefined policies have correct modes. Test custom policy creation.

```bash
git add ati-sdk-agent-client/ settings.gradle.kts
git commit -m "feat(agent-client): add ati-sdk-agent-client module with VerificationMode and VerificationPolicy"
```

---

## Task 13: CertificateCapturingTrustManager

**Files:**
- Create: `ati-sdk-agent-client/src/main/java/com/aliyun/ati/sdk/agent/http/CertificateCapturingTrustManager.java`
- Create: `ati-sdk-agent-client/src/main/java/com/aliyun/ati/sdk/agent/http/AtiVerifiedSslContextFactory.java`
- Create tests

- [ ] **Step 1: Implement CertificateCapturingTrustManager**

Wraps standard `X509TrustManager`. During `checkServerTrusted`, delegates to wrapped manager then saves the cert chain per hostname in a `ConcurrentHashMap`.

- [ ] **Step 2: Implement AtiVerifiedSslContextFactory**

Creates `SSLContext` with `CertificateCapturingTrustManager`. Optionally loads client keystore for mTLS.

- [ ] **Step 3: Write tests and commit**

```bash
git add ati-sdk-agent-client/src/
git commit -m "feat(agent-client): add CertificateCapturingTrustManager and SslContextFactory"
```

---

## Task 14: DANE TlsaVerifier

**Files:**
- Create: `ati-sdk-agent-client/src/main/java/com/aliyun/ati/sdk/agent/verification/VerificationResult.java`
- Create: `ati-sdk-agent-client/src/main/java/com/aliyun/ati/sdk/agent/verification/DaneTlsaVerifier.java`
- Create tests

- [ ] **Step 1: Implement VerificationResult**

```java
package com.aliyun.ati.sdk.agent.verification;

public final class VerificationResult {

    public enum Type { DANE, BADGE, PKI_ONLY }
    public enum Status { SUCCESS, MISMATCH, NOT_FOUND, ERROR }

    private final Type type;
    private final Status status;
    private final String detail;

    // constructor, getters, static factories: success(Type), failure(Type, Status, detail)
}
```

- [ ] **Step 2: Implement DaneTlsaVerifier**

Uses dnsjava to query `_443._tcp.{host}` TLSA records. Compares cert fingerprint from TLSA record with actual server cert fingerprint. Method: `VerificationResult verify(String host, int port, X509Certificate serverCert)`.

- [ ] **Step 3: Write tests and commit**

```bash
git add ati-sdk-agent-client/src/
git commit -m "feat(agent-client): add DaneTlsaVerifier for DANE TLSA verification"
```

---

## Task 15: BadgeVerifier + DefaultConnectionVerifier

**Files:**
- Create: `ati-sdk-agent-client/src/main/java/com/aliyun/ati/sdk/agent/verification/BadgeVerifier.java`
- Create: `ati-sdk-agent-client/src/main/java/com/aliyun/ati/sdk/agent/verification/DefaultConnectionVerifier.java`
- Create tests

- [ ] **Step 1: Implement BadgeVerifier**

Wraps `BadgeVerificationService`. Method: `VerificationResult verify(String agentId, X509Certificate serverCert)`.
1. Call `badgeVerificationService.verifyServer(agentId)` → `ServerVerificationResult`
2. If status != VERIFIED, return failure
3. Compare `serverCertFingerprint` from result with actual cert fingerprint using `CertUtils.fingerprintMatches()`

- [ ] **Step 2: Implement DefaultConnectionVerifier**

Orchestrates DANE + Badge based on `VerificationPolicy`:
- `preVerify(AtiAgentDescriptor)` — parallel pre-fetch of DANE + Badge data
- `postVerify(X509Certificate serverCert)` — compare captured cert against DANE/Badge expectations
- Respects `VerificationMode`: DISABLED skips, ADVISORY logs warning on failure, REQUIRED throws

- [ ] **Step 3: Write tests and commit**

```bash
git add ati-sdk-agent-client/src/
git commit -m "feat(agent-client): add BadgeVerifier and DefaultConnectionVerifier"
```

---

## Task 16: ConnectOptions + AtiConnection + AtiVerifiedClient

**Files:**
- Create: `ati-sdk-agent-client/src/main/java/com/aliyun/ati/sdk/agent/ConnectOptions.java`
- Create: `ati-sdk-agent-client/src/main/java/com/aliyun/ati/sdk/agent/AtiConnection.java`
- Create: `ati-sdk-agent-client/src/main/java/com/aliyun/ati/sdk/agent/AtiVerifiedClient.java`
- Create tests

- [ ] **Step 1: Implement ConnectOptions (Builder pattern)**

Fields: `policy` (VerificationPolicy, default DANE_AND_BADGE), `port` (int, default 443), `keystorePath` (String, nullable), `keystorePassword` (String, nullable).

- [ ] **Step 2: Implement AtiConnection**

Holds the verified `HttpClient` + `AtiAgentDescriptor` + `VerificationResult` list. Exposes `getHttpClient()`, `getVerificationResults()`.

- [ ] **Step 3: Implement AtiVerifiedClient (Builder pattern)**

Constructor takes `AtiDiscoveryClient`, `DefaultConnectionVerifier`, `AtiVerifiedSslContextFactory`.

`connect(AtiName, ConnectOptions)`:
1. `discoveryClient.discover(name)` → `AtiAgentDescriptor`
2. `connectionVerifier.preVerify(descriptor)` — pre-fetch DANE + Badge
3. Create `SSLContext` via `AtiVerifiedSslContextFactory` (with mTLS if keystore configured)
4. Build `HttpClient` with the SSL context
5. `connectionVerifier.postVerify(capturedCert)` — validate cert
6. Return `AtiConnection`

- [ ] **Step 4: Write tests and commit**

```bash
git add ati-sdk-agent-client/src/
git commit -m "feat(agent-client): add AtiVerifiedClient with two-phase verification flow"
```

---

## Task 17: ClientRequestVerifier (ATI Server side)

**Files:**
- Create: `ati-sdk-agent-client/src/main/java/com/aliyun/ati/sdk/agent/server/ClientRequestVerifier.java`
- Create tests

- [ ] **Step 1: Implement ClientRequestVerifier**

Constructor takes `BadgeVerificationService`.

`verify(X509Certificate clientCert)`:
1. Compute client cert fingerprint via `CertUtils.sha256Fingerprint(clientCert)`
2. Extract agentHost from cert CN (Common Name)
3. Call `badgeVerificationService.verifyClient(agentId)` → `ClientVerificationResult`
4. Compare `identityCertFingerprint` with actual client cert fingerprint
5. Return `ClientVerificationResult`

- [ ] **Step 2: Write tests and commit**

```bash
git add ati-sdk-agent-client/src/
git commit -m "feat(agent-client): add ClientRequestVerifier for ATI Server side mTLS verification"
```

---

## Task 18: Spring Boot Starter

**Files:**
- Create: `ati-sdk-spring-boot-starter/build.gradle.kts`
- Modify: `settings.gradle.kts` — add `include("ati-sdk-spring-boot-starter")`
- Modify: `gradle.properties` — add `springBootVersion=3.2.1`
- Create: `ati-sdk-spring-boot-starter/src/main/java/com/aliyun/ati/sdk/spring/AtiSdkProperties.java`
- Create: `ati-sdk-spring-boot-starter/src/main/java/com/aliyun/ati/sdk/spring/AtiClientAutoConfiguration.java`
- Create: `ati-sdk-spring-boot-starter/src/main/java/com/aliyun/ati/sdk/spring/AtiServerAutoConfiguration.java`
- Create: `ati-sdk-spring-boot-starter/src/main/resources/META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`
- Create tests

- [ ] **Step 1: Create module build file**

```kotlin
val springBootVersion by project

dependencies {
    api(project(":ati-sdk-agent-client"))
    implementation("org.springframework.boot:spring-boot-autoconfigure:$springBootVersion")
    compileOnly("org.springframework:spring-web:6.1.2")

    testImplementation("org.springframework.boot:spring-boot-starter-test:$springBootVersion")
    testImplementation("org.junit.jupiter:junit-jupiter:${project.property("junitVersion")}")
    testImplementation("org.assertj:assertj-core:${project.property("assertjVersion")}")
}
```

- [ ] **Step 2: Implement AtiSdkProperties**

```java
@ConfigurationProperties(prefix = "ati.sdk")
public class AtiSdkProperties {
    private String mode = "client";
    private Transparency transparency = new Transparency();
    private Verification verification = new Verification();
    private Client client = new Client();
    private Server server = new Server();

    // inner classes for Transparency (baseUrl), Verification (policy),
    // Client (dnsTimeout, connectTimeout, mtls keystore),
    // Server (mtls keystore)
    // getters + setters
}
```

- [ ] **Step 3: Implement AtiClientAutoConfiguration**

`@Configuration` + `@ConditionalOnProperty(name = "ati.sdk.mode", havingValue = "client", matchIfMissing = true)`.

Registers beans: `AtiTransparencyClient`, `RootKeyManager`, `BadgeVerificationService`, `CachingBadgeVerificationService`, `AtiVerifiedClient`.

Also activates when `mode=both`.

- [ ] **Step 4: Implement AtiServerAutoConfiguration**

`@ConditionalOnProperty(name = "ati.sdk.mode", havingValue = "server")`.

Registers beans: `AtiTransparencyClient`, `RootKeyManager`, `BadgeVerificationService`, `ClientRequestVerifier`.

Also activates when `mode=both`.

- [ ] **Step 5: Create auto-configuration registration file**

`src/main/resources/META-INF/spring/org.springframework.boot.autoconfigure.AutoConfiguration.imports`:
```
com.aliyun.ati.sdk.spring.AtiClientAutoConfiguration
com.aliyun.ati.sdk.spring.AtiServerAutoConfiguration
```

- [ ] **Step 6: Write integration tests**

Use `ApplicationContextRunner` to verify beans are registered when correct properties are set.

- [ ] **Step 7: Run tests and commit**

```bash
git add ati-sdk-spring-boot-starter/ settings.gradle.kts gradle.properties
git commit -m "feat(spring): add ati-sdk-spring-boot-starter with client/server auto-configuration"
```

---

## Task 19: Full build verification

- [ ] **Step 1: Run full build**

```bash
gradle clean build
```

Expected: All modules compile and all tests pass.

- [ ] **Step 2: Verify checkstyle passes**

```bash
gradle checkstyleMain checkstyleTest
```

- [ ] **Step 3: Final commit with updated settings**

```bash
git add -A
git status
git commit -m "chore: finalize multi-module build for ATI SDK"
```
