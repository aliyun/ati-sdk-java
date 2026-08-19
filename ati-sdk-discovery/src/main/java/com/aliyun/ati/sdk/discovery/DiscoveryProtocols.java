package com.aliyun.ati.sdk.discovery;

/**
 * Maps Discovery TXT {@code p=} Protocol values to Endpoint Protocol names.
 */
final class DiscoveryProtocols {

    private DiscoveryProtocols() {
    }

    static boolean isSupported(String txtProtocol) {
        return switch (txtProtocol == null ? "" : txtProtocol) {
            case "mcp", "a2a", "http-api" -> true;
            default -> false;
        };
    }

    static String toEndpointProtocol(String txtProtocol) {
        if (!isSupported(txtProtocol)) {
            throw new IllegalArgumentException("Unsupported protocol: " + txtProtocol);
        }
        return switch (txtProtocol) {
            case "mcp" -> "MCP";
            case "a2a" -> "A2A";
            case "http-api" -> "HTTP-API";
            default -> throw new IllegalArgumentException("Unsupported protocol: " + txtProtocol);
        };
    }
}
