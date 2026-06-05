package com.aliyun.ati.sdk.spring;

import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Configuration properties for the ATI SDK Spring Boot starter.
 *
 * <p>All properties are prefixed with {@code ati.sdk}.
 */
@ConfigurationProperties(prefix = "ati.sdk")
public class AtiSdkProperties {

    private String mode = "client";
    private Transparency transparency = new Transparency();
    private Verification verification = new Verification();
    private Client client = new Client();
    private Server server = new Server();
    private Idca idca = new Idca();
    private Identity identity = new Identity();

    public String getMode() {
        return mode;
    }

    public void setMode(String mode) {
        this.mode = mode;
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

    public Server getServer() {
        return server;
    }

    public void setServer(Server server) {
        this.server = server;
    }

    public Idca getIdca() {
        return idca;
    }

    public void setIdca(Idca idca) {
        this.idca = idca;
    }

    public Identity getIdentity() {
        return identity;
    }

    public void setIdentity(Identity identity) {
        this.identity = identity;
    }

    /**
     * Transparency Log configuration.
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

        private String policy = "DANE_AND_BADGE";

        public String getPolicy() {
            return policy;
        }

        public void setPolicy(String policy) {
            this.policy = policy;
        }
    }

    /**
     * Client-side configuration.
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

    /**
     * Server-side configuration.
     */
    public static class Server {
    }

    /**
     * Agent identity certificate configuration (PEM format).
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
     * IDCA (Identity CA) chain verification configuration.
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
}
