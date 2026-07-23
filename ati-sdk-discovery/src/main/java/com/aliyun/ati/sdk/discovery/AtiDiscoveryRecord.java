package com.aliyun.ati.sdk.discovery;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Parsed {@code _ati} DNS TXT record for agent discovery.
 *
 * <p>Format: {@code v=ati1; av=v1.0.0; p=mcp; u=https://...; m=direct}</p>
 */
public final class AtiDiscoveryRecord {

    public static final String FORMAT_ATI1 = "ati1";
    public static final String MODE_DIRECT = "direct";

    private final String formatVersion;
    private final String agentVersion;
    private final String protocol;
    private final String agentUrl;
    private final String mode;

    private AtiDiscoveryRecord(String formatVersion,
                               String agentVersion,
                               String protocol,
                               String agentUrl,
                               String mode) {
        this.formatVersion = formatVersion;
        this.agentVersion = agentVersion;
        this.protocol = protocol;
        this.agentUrl = agentUrl;
        this.mode = mode;
    }

    /**
     * Parses a DNS TXT record string.
     *
     * @param txt raw TXT value
     * @return parsed record
     * @throws IllegalArgumentException if malformed or unsupported format/mode
     */
    public static AtiDiscoveryRecord parse(String txt) {
        Objects.requireNonNull(txt, "TXT record must not be null");
        Map<String, String> fields = parseFields(txt);

        String v = fields.get("v");
        if (!FORMAT_ATI1.equals(v)) {
            throw new IllegalArgumentException("Expected v=ati1, got: " + v);
        }

        String av = fields.get("av");
        if (av == null || av.isBlank()) {
            throw new IllegalArgumentException("Missing required field: av");
        }

        String p = fields.get("p");
        if (p == null || p.isBlank()) {
            throw new IllegalArgumentException("Missing required field: p");
        }

        String u = fields.get("u");
        if (u == null || u.isBlank()) {
            throw new IllegalArgumentException("Missing required field: u");
        }

        String mode = fields.getOrDefault("m", MODE_DIRECT);
        if (!MODE_DIRECT.equalsIgnoreCase(mode)) {
            throw new IllegalArgumentException("Unsupported discovery mode: " + mode);
        }

        return new AtiDiscoveryRecord(v, av, p, u, mode.toLowerCase());
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

    public String getAgentVersion() {
        return agentVersion;
    }

    public String getProtocol() {
        return protocol;
    }

    public String getAgentUrl() {
        return agentUrl;
    }

    public String getMode() {
        return mode;
    }
}
