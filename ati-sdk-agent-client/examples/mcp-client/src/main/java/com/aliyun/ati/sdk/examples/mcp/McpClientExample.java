package com.aliyun.ati.sdk.examples.mcp;

import com.aliyun.ati.sdk.agent.AtiConnection;
import com.aliyun.ati.sdk.agent.AtiVerifiedClient;
import com.aliyun.ati.sdk.agent.VerificationPolicy;
import com.aliyun.ati.sdk.agent.verification.VerificationResult;
import com.aliyun.ati.sdk.transparency.TransparencyClient;

import io.modelcontextprotocol.client.McpClient;
import io.modelcontextprotocol.client.McpSyncClient;
import io.modelcontextprotocol.client.transport.HttpClientStreamableHttpTransport;
import io.modelcontextprotocol.spec.McpSchema.ClientCapabilities;

import java.time.Duration;

/**
 * MCP Client Example - demonstrates ATI verification with the MCP SDK.
 *
 * <p>This example shows how to integrate ATI verification with the official
 * MCP (Model Context Protocol) Java SDK using the high-level {@link AtiVerifiedClient}.</p>
 *
 * <p>The client:</p>
 * <ul>
 *   <li>Automatically configures verification based on the selected policy</li>
 *   <li>Handles DANE/TLSA and Badge verification methods</li>
 *   <li>Uses mTLS with an identity certificate for mutual authentication</li>
 *   <li>Post-verifies the server certificate against transparency log and/or TLSA records</li>
 * </ul>
 *
 * <h2>Usage</h2>
 * <pre>
 * ./gradlew :ati-sdk-agent-client:examples:mcp-client:run
 * ./gradlew :ati-sdk-agent-client:examples:mcp-client:run --args="https://your-server.com/mcp"
 * </pre>
 *
 * <h2>Environment Variables</h2>
 * <ul>
 *   <li>KEYSTORE_PATH - Path to client PKCS12 keystore containing identity cert + key</li>
 *   <li>KEYSTORE_PASS - Keystore password (default: changeit)</li>
 *   <li>ATI_POLICY - Verification policy: PKI_ONLY, BADGE_REQUIRED (default), DANE_AND_BADGE</li>
 * </ul>
 *
 * <h2>Creating a Client Keystore</h2>
 * <pre>
 * # From PEM files:
 * openssl pkcs12 -export -in cert.pem -inkey key.pem -out client.p12 -name client -password pass:changeit
 *
 * # Include CA chain if needed:
 * openssl pkcs12 -export -in cert.pem -inkey key.pem -certfile ca.pem -out client.p12 -name client
 * </pre>
 */
public class McpClientExample {

    private static final String DEFAULT_SERVER_URL = "https://your-mcp-server.example.com/mcp";

    public static void main(String[] args) throws Exception {
        String serverUrl = args.length > 0 ? args[0] : DEFAULT_SERVER_URL;

        // Client keystore for mTLS identity certificate
        String keystorePath = System.getenv("KEYSTORE_PATH");
        String keystorePassword = System.getenv("KEYSTORE_PASS");

        // Policy selection via environment variable
        String policyStr = System.getenv("ATI_POLICY");
        VerificationPolicy policy = parsePolicy(policyStr);

        System.out.println("ATI SDK - MCP Client Example");
        System.out.println("Target: " + serverUrl);
        System.out.println("Policy: " + policy);
        System.out.println();

        // Create ATI verified client - handles all verification setup based on policy
        try (AtiVerifiedClient atiClient = AtiVerifiedClient.builder()
                .keyStorePath(keystorePath, keystorePassword != null ? keystorePassword : "changeit")
                .transparencyClient(TransparencyClient.builder()
                    .baseUrl(TransparencyClient.CNNIC_BASE_URL).build())
                .policy(policy)
                .connectTimeout(Duration.ofSeconds(30))
                .build()) {

            // Connect and run all pre-verifications (DANE, Badge based on policy)
            try (AtiConnection connection = atiClient.connect(serverUrl)) {
                System.out.println("Pre-verification complete:");
                System.out.println("  DANE records: " + (connection.hasDaneRecords() ? "found" : "none"));
                System.out.println("  Badge registration: " + (connection.hasBadgeRegistration() ? "found" : "none"));

                // Create MCP client with ATI SSLContext (enables mTLS + certificate capture)
                HttpClientStreamableHttpTransport transport = HttpClientStreamableHttpTransport.builder(serverUrl)
                    .customizeClient(b -> b.sslContext(atiClient.sslContext())
                        .connectTimeout(Duration.ofSeconds(30)))
                    .build();

                McpSyncClient mcpClient = McpClient.sync(transport)
                    .requestTimeout(Duration.ofSeconds(30))
                    .capabilities(ClientCapabilities.builder().roots(true).build())
                    .build();

                try {
                    mcpClient.initialize();

                    // Post-verify server certificate (combines all results per policy)
                    VerificationResult result = connection.verifyServer();
                    System.out.println("\nServer verification: " + (result.isSuccess() ? "PASS" : "FAIL"));
                    System.out.println("  Type: " + result.type());
                    if (result.reason() != null) {
                        System.out.println("  Reason: " + result.reason());
                    }

                    if (!result.isSuccess()) {
                        throw new SecurityException("Server verification failed: " + result.reason());
                    }

                    // Use verified MCP client
                    var tools = mcpClient.listTools();
                    System.out.println("\nAvailable tools: " + tools.tools().size());
                    tools.tools().forEach(t -> System.out.println("  - " + t.name() + ": " + t.description()));

                    // Call a tool (example)
                    if (!tools.tools().isEmpty()) {
                        var firstTool = tools.tools().get(0);
                        System.out.println("\nCalling tool: " + firstTool.name());
                        var callResult = mcpClient.callTool(
                            new io.modelcontextprotocol.spec.McpSchema.CallToolRequest(
                                firstTool.name(), java.util.Map.of()));
                        System.out.println("  Result: " + truncate(callResult.content().toString(), 200));
                    }

                } finally {
                    mcpClient.closeGracefully();
                }
            }
        }
    }

    private static VerificationPolicy parsePolicy(String policyStr) {
        if (policyStr == null || policyStr.isBlank()) {
            return VerificationPolicy.BADGE_REQUIRED;
        }
        return switch (policyStr.toUpperCase()) {
            case "PKI_ONLY" -> VerificationPolicy.PKI_ONLY;
            case "DANE_AND_BADGE" -> VerificationPolicy.DANE_AND_BADGE;
            default -> VerificationPolicy.BADGE_REQUIRED;
        };
    }

    private static String truncate(String s, int maxLen) {
        if (s == null) {
            return "null";
        }
        s = s.replace("\n", " ").trim();
        return s.length() > maxLen ? s.substring(0, maxLen) + "..." : s;
    }
}
