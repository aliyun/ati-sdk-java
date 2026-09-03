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
 *     identity:
 *       certificate: /path/to/identity.crt
 *       private-key: /path/to/identity.key
 *     server:
 *       certificate: /path/to/server.crt
 *       private-key: /path/to/server.key
 *       port: 443
 *       verification:
 *         policy: BASIC          # NONE | BASIC | ENHANCED | ADVANCED
 *       idca:
 *         trust-certificate: /path/to/idca-trust.pem  # optional; replaces shipped IDCA Chain
 *     transparency:
 *       base-url: https://ati-tl.cnnic.cn
 *     verification:
 *       policy: ENHANCED       # BASIC | ENHANCED | ADVANCED (client; NONE is server-only)
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
        private Verification verification = new Verification("BASIC");
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
     * IDCA (Identity CA) trust configuration. When unset, the SDK-shipped production
     * IDCA Chain is used. A configured path replaces that chain entirely.
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
        private String baseUrl = "https://ati-tl.cnnic.cn";
        private boolean skipTlsVerification = false;

        public String getBaseUrl() {
            return baseUrl;
        }

        public void setBaseUrl(String baseUrl) {
            this.baseUrl = baseUrl;
        }

        public boolean isSkipTlsVerification() {
            return skipTlsVerification;
        }

        public void setSkipTlsVerification(boolean skipTlsVerification) {
            this.skipTlsVerification = skipTlsVerification;
        }
    }

    /**
     * Verification policy configuration.
     */
    public static class Verification {
        private String policy = "ENHANCED";

        public Verification() {
        }

        /**
         * Creates a Verification with the specified default policy.
         *
         * @param defaultPolicy the default policy value
         */
        public Verification(String defaultPolicy) {
            this.policy = defaultPolicy;
        }

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
