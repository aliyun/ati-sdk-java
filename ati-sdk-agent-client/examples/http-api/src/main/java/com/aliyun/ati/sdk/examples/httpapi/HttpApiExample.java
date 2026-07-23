package com.aliyun.ati.sdk.examples.httpapi;

import com.aliyun.ati.sdk.agent.AtiClient;
import com.aliyun.ati.sdk.agent.ConnectOptions;
import com.aliyun.ati.sdk.agent.VerificationPolicy;
import com.aliyun.ati.sdk.agent.connection.AgentConnection;
import com.aliyun.ati.sdk.agent.protocol.HttpApiClient;
import com.aliyun.ati.sdk.transparency.TransparencyClient;

import java.time.Duration;

/**
 * HTTP API Example - demonstrates ATI verification with AtiClient.
 *
 * <p>This example shows how to use the ATI SDK to make verified HTTP
 * connections to ATI-registered agents using different verification policies.</p>
 *
 * <h2>Prerequisites</h2>
 * <ol>
 *   <li>A running ATI-registered agent with HTTPS endpoint</li>
 *   <li>For DANE verification: TLSA DNS records configured for the agent's hostname</li>
 *   <li>For Badge verification: Agent registered in ATI transparency log (CNNIC TL)</li>
 * </ol>
 *
 * <h2>Usage</h2>
 * <pre>
 * # Run with default settings
 * ./gradlew :ati-sdk-agent-client:examples:http-api:run
 *
 * # Run with custom server URL
 * ./gradlew :ati-sdk-agent-client:examples:http-api:run --args="https://your-agent.example.com:8443"
 * </pre>
 *
 * <h2>Verification Policies</h2>
 * <ul>
 *   <li><b>BASIC</b> - Standard HTTPS with system trust store</li>
 *   <li><b>ENHANCED</b> - Requires transparency log verification (recommended default)</li>
 *   <li><b>ADVANCED</b> - Requires both DANE and Badge verification</li>
 * </ul>
 */
public class HttpApiExample {

    public static void main(String[] args) {
        String serverUrl = args.length > 0 ? args[0] : "https://your-agent.example.com:8443";

        System.out.println("===========================================");
        System.out.println("ATI SDK - HTTP API Example");
        System.out.println("===========================================");
        System.out.println("Target: " + serverUrl);
        System.out.println();

        examplePkiOnly(serverUrl);
        exampleBadgeRequired(serverUrl);
        exampleDaneAndBadge(serverUrl);

        System.out.println("\n===========================================");
        System.out.println("Examples completed!");
        System.out.println("===========================================");
    }

    /**
     * Example 1: BASIC - Standard HTTPS.
     *
     * <p>Uses the system trust store for certificate validation.
     * This is the simplest approach but provides no ATI-specific verification.</p>
     */
    private static void examplePkiOnly(String serverUrl) {
        System.out.println("Example 1: BASIC - Standard HTTPS");
        System.out.println("-".repeat(40));

        try {
            AtiClient client = AtiClient.builder()
                .connectTimeout(Duration.ofSeconds(10))
                .readTimeout(Duration.ofSeconds(30))
                .build();

            System.out.println("  Created AtiClient");

            AgentConnection conn = client.connect(serverUrl, ConnectOptions.builder()
                .verificationPolicy(VerificationPolicy.BASIC)
                .build());
            System.out.println("  Connected with BASIC");

            HttpApiClient api = conn.httpApiAt(serverUrl);
            String response = api.get("/health");
            System.out.println("  GET /health: " + truncate(response, 100));

            System.out.println("  [SUCCESS] BASIC example completed\n");

        } catch (Exception e) {
            System.out.println("  [ERROR] " + e.getMessage() + "\n");
        }
    }

    /**
     * Example 2: ENHANCED - Transparency log verification.
     *
     * <p>Verifies the agent's certificate against the ATI transparency log (CNNIC TL).
     * This is the recommended approach for most use cases.</p>
     */
    private static void exampleBadgeRequired(String serverUrl) {
        System.out.println("Example 2: ENHANCED - Transparency Log Verification");
        System.out.println("-".repeat(40));

        try {
            AtiClient client = AtiClient.create();
            System.out.println("  Created AtiClient");

            ConnectOptions options = ConnectOptions.builder()
                .verificationPolicy(VerificationPolicy.ENHANCED)
                .transparencyClient(TransparencyClient.builder()
                    .baseUrl(TransparencyClient.CNNIC_BASE_URL).build())
                .build();

            System.out.println("  Connecting with: " + options.getVerificationPolicy());
            System.out.println("  Will verify certificate against ATI transparency log (CNNIC TL)");

            AgentConnection conn = client.connect(serverUrl, options);
            System.out.println("  Connected with ENHANCED");

            HttpApiClient api = conn.httpApiAt(serverUrl);
            String response = api.get("/health");
            System.out.println("  GET /health: " + truncate(response, 100));

            System.out.println("  [SUCCESS] ENHANCED example completed\n");

        } catch (Exception e) {
            System.out.println("  [ERROR] " + e.getMessage());
            if (e.getMessage() != null && e.getMessage().contains("transparency")) {
                System.out.println("  (Agent may not be registered in the transparency log)");
            }
            System.out.println();
        }
    }

    /**
     * Example 3: DANE + Badge verification (maximum security).
     *
     * <p>Demonstrates full verification with both DANE and Badge required.
     * DANE uses DNSSEC-secured TLSA records to verify the server certificate.
     * Badge uses the transparency log to verify agent registration.</p>
     */
    private static void exampleDaneAndBadge(String serverUrl) {
        System.out.println("Example 3: DANE + Badge (Full Verification)");
        System.out.println("-".repeat(40));

        try {
            AtiClient client = AtiClient.create();

            ConnectOptions options = ConnectOptions.builder()
                .verificationPolicy(VerificationPolicy.ADVANCED)
                .transparencyClient(TransparencyClient.builder()
                    .baseUrl(TransparencyClient.CNNIC_BASE_URL).build())
                .build();

            System.out.println("  Connecting with full verification policy:");
            System.out.println("    DANE: Required (verify TLSA DNS record)");
            System.out.println("    Badge: Required (verify transparency log)");

            AgentConnection conn = client.connect(serverUrl, options);
            HttpApiClient api = conn.httpApiAt(serverUrl);
            String response = api.get("/health");
            System.out.println("  GET /health: " + truncate(response, 100));

            System.out.println("  [SUCCESS] DANE + Badge example completed\n");

        } catch (Exception e) {
            System.out.println("  [ERROR] " + e.getMessage());
            if (e.getMessage() != null && e.getMessage().contains("DANE")) {
                System.out.println("  (Agent may not have TLSA DNS records configured)");
            }
            System.out.println();
        }
    }

    private static String truncate(String s, int maxLen) {
        if (s == null) {
            return "null";
        }
        s = s.replace("\n", " ").trim();
        return s.length() > maxLen ? s.substring(0, maxLen) + "..." : s;
    }
}
