package com.aliyun.ati.sdk.discovery;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Represents a parsed ATI badge TXT record from {@code _ati-badge.{agentHost}}.
 *
 * <p>Format: {@code v=ati-badge1; version=v1.0.0; url=https://tl.ansagent.cn:8180/tl/agents/{id}}
 */
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

    /**
     * Parses a DNS TXT record string into an {@code AtiBadgeRecord}.
     *
     * @param txt the raw TXT record value
     * @return the parsed record
     * @throws NullPointerException     if txt is null
     * @throws IllegalArgumentException if the record is malformed
     */
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

    public String getFormatVersion() {
        return formatVersion;
    }

    public String getVersion() {
        return version;
    }

    public String getUrl() {
        return url;
    }

    public String getAgentId() {
        return agentId;
    }
}
