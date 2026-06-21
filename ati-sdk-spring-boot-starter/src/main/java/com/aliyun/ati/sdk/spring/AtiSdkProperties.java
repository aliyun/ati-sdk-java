package com.aliyun.ati.sdk.spring;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration properties for ATI SDK.
 *
 * <p>Properties are bound from the {@code ati.sdk} prefix in application properties.</p>
 *
 * <p>Example {@code application.yml}:</p>
 * <pre>
 * ati:
 *   sdk:
 *     mode: client
 *     discovery:
 *       endpoint: alidns.aliyuncs.com
 *       access-key-id: your-ak
 *       access-key-secret: your-sk
 *     identity:
 *       certificate: /path/to/identity.crt
 *       private-key: /path/to/identity.key
 *     server:
 *       certificate: /path/to/server.crt
 *       private-key: /path/to/server.key
 *       port: 443
 *       verification:
 *         policy: BADGE_REQUIRED
 *       idca:
 *         trust-certificate: /path/to/idca-trust.pem
 *     transparency:
 *       base-url: https://tl.ansagent.cn:8180
 *     verification:
 *       policy: BADGE_REQUIRED
 *     client:
 *       dns-timeout: 5s
 *       connect-timeout: 10s
 * </pre>
 */
@ConfigurationProperties(prefix = "ati.sdk")
public class AtiSdkProperties {

    /**
     * SDK mode: client, server, or both.
     */
    private String mode = "client";

    /**
     * Whether auto-configuration is enabled. Defaults to true.
     */
    private boolean enabled = true;

    private Discovery discovery = new Discovery();
    private Identity identity = new Identity();
    private Server server = new Server();
    private Transparency transparency = new Transparency();
    private Verification verification = new Verification();
    private Client client = new Client();

    public String getMode() {
        return mode;
    }

    public void setMode(String mode) {
        this.mode = mode;
    }

    public boolean isEnabled() {
        return enabled;
    }

    public void setEnabled(boolean enabled) {
        this.enabled = enabled;
    }

    public Discovery getDiscovery() {
        return discovery;
    }

    public void setDiscovery(Discovery discovery) {
        this.discovery = discovery;
    }

    public Identity getIdentity() {
        return identity;
    }

    public void setIdentity(Identity identity) {
        this.identity = identity;
    }

    public Server getServer() {
        return server;
    }

    public void setServer(Server server) {
        this.server = server;
    }

    public Transparency getTransparency() {
        return transparency;
    }

    public void setTransparency(Transparency transparency) {
        this.transparency = transparency;
    }

    public Verification getVerification() {
        return verification;
    }

    public void setVerification(Verification verification) {
        this.verification = verification;
    }

    public Client getClient() {
        return client;
    }

    public void setClient(Client client) {
        this.client = client;
    }

    /**
     * Returns true if mode is "client" or "both".
     */
    public boolean isClientMode() {
        return "client".equalsIgnoreCase(mode) || "both".equalsIgnoreCase(mode);
    }

    /**
     * Returns true if mode is "server" or "both".
     */
    public boolean isServerMode() {
        return "server".equalsIgnoreCase(mode) || "both".equalsIgnoreCase(mode);
    }

    /**
     * Discovery configuration for agent lookup via Alibaba Cloud OpenAPI.
     */
    public static class Discovery {
        private String endpoint = "alidns.aliyuncs.com";
        private String accessKeyId;
        private String accessKeySecret;

        public String getEndpoint() {
            return endpoint;
        }

        public void setEndpoint(String endpoint) {
            this.endpoint = endpoint;
        }

        public String getAccessKeyId() {
            return accessKeyId;
        }

        public void setAccessKeyId(String accessKeyId) {
            this.accessKeyId = accessKeyId;
        }

        public String getAccessKeySecret() {
            return accessKeySecret;
        }

        public void setAccessKeySecret(String accessKeySecret) {
            this.accessKeySecret = accessKeySecret;
        }
    }

    /**
     * Identity certificate configuration for mTLS client identity.
     */
    public static class Identity {
        private String certificate;
        private String privateKey;

        public String getCertificate() {
            return certificate;
        }

        public void setCertificate(String certificate) {
            this.certificate = certificate;
        }

        public String getPrivateKey() {
            return privateKey;
        }

        public void setPrivateKey(String privateKey) {
            this.privateKey = privateKey;
        }
    }

    /**
     * Server-side configuration for ATI agent servers.
     */
    public static class Server {
        private String certificate;
        private String privateKey;
        private int port = 443;
        private Verification verification = new Verification();
        private Idca idca = new Idca();

        public String getCertificate() {
            return certificate;
        }

        public void setCertificate(String certificate) {
            this.certificate = certificate;
        }

        public String getPrivateKey() {
            return privateKey;
        }

        public void setPrivateKey(String privateKey) {
            this.privateKey = privateKey;
        }

        public int getPort() {
            return port;
        }

        public void setPort(int port) {
            this.port = port;
        }

        public Verification getVerification() {
            return verification;
        }

        public void setVerification(Verification verification) {
            this.verification = verification;
        }

        public Idca getIdca() {
            return idca;
        }

        public void setIdca(Idca idca) {
            this.idca = idca;
        }
    }

    /**
     * IDCA (Identity CA) trust configuration.
     */
    public static class Idca {
        private String trustCertificate;

        public String getTrustCertificate() {
            return trustCertificate;
        }

        public void setTrustCertificate(String trustCertificate) {
            this.trustCertificate = trustCertificate;
        }
    }

    /**
     * Transparency log configuration.
     */
    public static class Transparency {
        private String baseUrl = "https://tl.ansagent.cn:8180";

        public String getBaseUrl() {
            return baseUrl;
        }

        public void setBaseUrl(String baseUrl) {
            this.baseUrl = baseUrl;
        }
    }

    /**
     * Verification policy configuration.
     */
    public static class Verification {
        private String policy = "BADGE_REQUIRED";

        public String getPolicy() {
            return policy;
        }

        public void setPolicy(String policy) {
            this.policy = policy;
        }
    }

    /**
     * Client-side connection configuration.
     */
    public static class Client {
        private String dnsTimeout = "5s";
        private String connectTimeout = "10s";

        public String getDnsTimeout() {
            return dnsTimeout;
        }

        public void setDnsTimeout(String dnsTimeout) {
            this.dnsTimeout = dnsTimeout;
        }

        public String getConnectTimeout() {
            return connectTimeout;
        }

        public void setConnectTimeout(String connectTimeout) {
            this.connectTimeout = connectTimeout;
        }
    }
}
