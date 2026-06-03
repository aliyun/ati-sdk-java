package com.aliyun.ati.sdk.discovery;

import java.util.Objects;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Represents an ATI name URI in the format {@code ati://v{version}.{agentHost}}.
 *
 * <p>Examples:
 * <ul>
 *   <li>{@code ati://v1.my-agent.example.com} - simple version</li>
 *   <li>{@code ati://v1.2.3.agent.example.com} - semantic version</li>
 * </ul>
 */
public final class AtiName {

    private static final String SCHEME = "ati://";
    private static final Pattern PATTERN = Pattern.compile(
        "^ati://v([0-9]+(?:\\.[0-9]+)*)\\.([a-zA-Z0-9][-a-zA-Z0-9]*(?:\\.[a-zA-Z0-9][-a-zA-Z0-9]*)+)$"
    );

    private final String version;
    private final String agentHost;

    private AtiName(String version, String agentHost) {
        this.version = version;
        this.agentHost = agentHost;
    }

    /**
     * Parses an ATI name URI string.
     *
     * @param uri the ATI name URI, e.g. {@code ati://v1.my-agent.example.com}
     * @return the parsed {@code AtiName}
     * @throws NullPointerException     if uri is null
     * @throws IllegalArgumentException if uri does not match the expected format
     */
    public static AtiName parse(String uri) {
        Objects.requireNonNull(uri, "ATI name URI must not be null");
        Matcher matcher = PATTERN.matcher(uri);
        if (!matcher.matches()) {
            throw new IllegalArgumentException(
                "Invalid ATI name: '" + uri + "'. Expected format: ati://v{version}.{agentHost}");
        }
        return new AtiName(matcher.group(1), matcher.group(2));
    }

    public String getVersion() {
        return version;
    }

    public String getAgentHost() {
        return agentHost;
    }

    /**
     * Returns the canonical URI representation of this ATI name.
     *
     * @return the URI string, e.g. {@code ati://v1.my-agent.example.com}
     */
    public String toUri() {
        return SCHEME + "v" + version + "." + agentHost;
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) {
            return true;
        }
        if (!(o instanceof AtiName other)) {
            return false;
        }
        return version.equals(other.version) && agentHost.equals(other.agentHost);
    }

    @Override
    public int hashCode() {
        return Objects.hash(version, agentHost);
    }

    @Override
    public String toString() {
        return toUri();
    }
}
