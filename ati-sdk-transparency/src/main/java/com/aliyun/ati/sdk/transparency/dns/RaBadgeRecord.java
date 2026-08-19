package com.aliyun.ati.sdk.transparency.dns;

import org.semver4j.Semver;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parsed {@code _ati-badge} DNS TXT record.
 *
 * <p>Format: {@code v=ati-badge1; av=v1.0.0; u=https://...}</p>
 *
 * <p><b>Security note (Spec 7.1):</b> The SDK extracts the full path from the TXT URL
 * and concatenates it with the configured TL base-url, rather than reconstructing a path
 * from the agent ID. This ensures that even if DNS is compromised, the SDK only talks to
 * the configured transparency log.</p>
 *
 * @param badgeVersion the badge format version (e.g., "ati-badge1")
 * @param agentVersion the agent's semantic version (e.g., "v1.0.0")
 * @param url the full transparency log URL from {@code u=}
 * @param agentId the extracted agent ID from the URL (kept for backwards compatibility)
 * @param tlPath the full path extracted from the URL (e.g., "/tl/agents/{uuid}/logs/latest")
 */
public record RaBadgeRecord(
    String badgeVersion,
    String agentVersion,
    String url,
    String agentId,
    String tlPath
) {
    public static final String FORMAT_ATI_BADGE1 = "ati-badge1";

    private static final Pattern AGENT_ID_PATTERN = Pattern.compile(
        "/(?:v1|tl)/agents/([a-f0-9-]+)",
        Pattern.CASE_INSENSITIVE
    );

    /**
     * Parses a TXT record value into an RaBadgeRecord.
     *
     * @param txtValue the raw TXT record value
     * @return the parsed record, or null if the format is invalid
     */
    public static RaBadgeRecord parse(String txtValue) {
        if (txtValue == null || txtValue.isBlank()) {
            return null;
        }

        Map<String, String> fields = parseFields(txtValue);

        String v = fields.get("v");
        if (!FORMAT_ATI_BADGE1.equals(v)) {
            return null;
        }

        String av = fields.get("av");
        if (av == null || av.isBlank() || parseAgentVersion(av) == null) {
            return null;
        }

        String u = fields.get("u");
        if (u == null || u.isBlank()) {
            return null;
        }

        return new RaBadgeRecord(v, av, u, extractAgentId(u), extractPath(u));
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

    /**
     * Extracts the agent ID from a transparency log URL.
     *
     * @param url the URL
     * @return the agent ID, or null if not found
     */
    private static String extractAgentId(String url) {
        if (url == null) {
            return null;
        }
        Matcher matcher = AGENT_ID_PATTERN.matcher(url);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }

    /**
     * Extracts the path portion from a transparency log URL.
     *
     * <p>Per spec 7.1, the SDK should extract the full path from the badge URL
     * and concatenate it with the configured TL base-url for security.</p>
     *
     * @param url the URL
     * @return the path portion (e.g., "/v1/agents/{uuid}"), or null if extraction fails
     */
    private static String extractPath(String url) {
        if (url == null) {
            return null;
        }
        try {
            return URI.create(url).getPath();
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Checks if this badge format version is supported.
     *
     * @return true if the badge format is {@code ati-badge1}
     */
    public boolean isSupportedBadgeFormat() {
        return FORMAT_ATI_BADGE1.equals(badgeVersion);
    }

    /**
     * Returns true if this record's {@code av} matches {@code version} after stripping
     * a leading {@code v} or {@code V} from both sides.
     *
     * @param version version from an Identity Certificate ATI Name (may be prefixed)
     * @return true if the versions are the same SemVer
     */
    public boolean matchesAgentVersion(String version) {
        if (version == null || agentVersion == null) {
            return false;
        }
        Semver badgeSemver = parseAgentVersion(agentVersion);
        Semver otherSemver = parseAgentVersion(version);
        return badgeSemver != null && otherSemver != null && badgeSemver.isEquivalentTo(otherSemver);
    }

    private static Semver parseAgentVersion(String av) {
        String normalized = av.startsWith("v") || av.startsWith("V") ? av.substring(1) : av;
        return Semver.parse(normalized);
    }

    @Override
    public String toString() {
        return "RaBadgeRecord{" +
            "badgeVersion='" + badgeVersion + "'" +
            ", agentVersion='" + agentVersion + "'" +
            ", url='" + url + "'" +
            ", agentId='" + agentId + "'" +
            ", tlPath='" + tlPath + "'" +
            "}";
    }
}
