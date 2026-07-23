package com.aliyun.ati.sdk.discovery;

import java.util.Locale;

/**
 * Normalizes protocol values from Discovery TXT to SDK endpoint conventions.
 */
final class DiscoveryProtocols {

    private DiscoveryProtocols() {
    }

    static String toEndpointProtocol(String txtProtocol) {
        if (txtProtocol == null || txtProtocol.isBlank()) {
            throw new IllegalArgumentException("protocol must not be blank");
        }
        return switch (txtProtocol.toLowerCase(Locale.ROOT)) {
            case "mcp" -> "MCP";
            case "a2a" -> "A2A";
            case "http-api" -> "HTTP-API";
            default -> txtProtocol.toUpperCase(Locale.ROOT);
        };
    }
}
