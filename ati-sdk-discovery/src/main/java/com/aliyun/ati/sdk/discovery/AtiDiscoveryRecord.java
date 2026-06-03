package com.aliyun.ati.sdk.discovery;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Represents a parsed ATI discovery TXT record from {@code _ati.{agentHost}}.
 *
 * <p>Format: {@code v=ati1; version=v1.0.0; url=...; mode=card|direct}
 */
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

    /**
     * Parses a DNS TXT record string into an {@code AtiDiscoveryRecord}.
     *
     * @param txt the raw TXT record value
     * @return the parsed record
     * @throws NullPointerException     if txt is null
     * @throws IllegalArgumentException if the record is malformed
     */
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

    public String getFormatVersion() {
        return formatVersion;
    }

    public String getVersion() {
        return version;
    }

    public String getUrl() {
        return url;
    }

    public String getMode() {
        return mode;
    }
}
