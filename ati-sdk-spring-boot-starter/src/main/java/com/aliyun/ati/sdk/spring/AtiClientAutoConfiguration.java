package com.aliyun.ati.sdk.spring;

import java.net.http.HttpClient;
import java.time.Duration;

import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.aliyun.ati.sdk.agent.AtiVerifiedClient;
import com.aliyun.ati.sdk.agent.VerificationPolicy;
import com.aliyun.ati.sdk.agent.verification.BadgeVerifier;
import com.aliyun.ati.sdk.agent.verification.DaneTlsaVerifier;
import com.aliyun.ati.sdk.agent.verification.DefaultConnectionVerifier;
import com.aliyun.ati.sdk.agent.verification.IdcaChainVerifier;
import com.aliyun.ati.sdk.discovery.AtiDiscoveryClient;
import com.aliyun.ati.sdk.discovery.DnsAtiDiscoveryClient;
import com.aliyun.ati.sdk.transparency.AtiTransparencyClient;
import com.aliyun.ati.sdk.transparency.verification.BadgeVerificationService;
import com.aliyun.ati.sdk.transparency.verification.CachingBadgeVerificationService;
import com.aliyun.ati.sdk.transparency.verification.MerkleProofVerifier;
import com.aliyun.ati.sdk.transparency.verification.TlSealVerifier;

/**
 * Auto-configuration for ATI SDK client beans.
 *
 * <p>Activates when {@code ati.sdk.mode} is "client" (the default) or "both".
 * Registers all beans needed for agent discovery and verified connections.
 */
@Configuration
@ConditionalOnExpression(
    "'${ati.sdk.mode:client}' != 'server'"
)
@EnableConfigurationProperties(AtiSdkProperties.class)
public class AtiClientAutoConfiguration {

    @Bean
    public AtiTransparencyClient atiTransparencyClient(
            AtiSdkProperties props) {
        Duration connectTimeout = Duration.parse(
            "PT" + props.getClient().getConnectTimeout());
        HttpClient httpClient = HttpClient.newBuilder()
            .connectTimeout(connectTimeout)
            .build();
        return new AtiTransparencyClient(
            props.getTransparency().getBaseUrl(), httpClient);
    }

    @Bean
    public TlSealVerifier tlSealVerifier() {
        return new TlSealVerifier();
    }

    @Bean
    public MerkleProofVerifier merkleProofVerifier() {
        return new MerkleProofVerifier();
    }

    @Bean
    public BadgeVerificationService badgeVerificationService(
            AtiTransparencyClient client,
            TlSealVerifier sealVerifier,
            MerkleProofVerifier merkleVerifier) {
        return new BadgeVerificationService(
            client, sealVerifier, merkleVerifier);
    }

    @Bean
    public CachingBadgeVerificationService cachingBadgeVerificationService(
            BadgeVerificationService service) {
        return new CachingBadgeVerificationService(service);
    }

    @Bean
    public AtiDiscoveryClient atiDiscoveryClient(AtiSdkProperties props) {
        Duration dnsTimeout = Duration.parse(
            "PT" + props.getClient().getDnsTimeout());
        return new DnsAtiDiscoveryClient(dnsTimeout);
    }

    @Bean
    public DaneTlsaVerifier daneTlsaVerifier() {
        return new DaneTlsaVerifier();
    }

    @Bean
    public BadgeVerifier badgeVerifier(
            CachingBadgeVerificationService service) {
        return new BadgeVerifier(service);
    }

    @Bean
    @ConditionalOnMissingBean
    @ConditionalOnProperty(prefix = "ati.sdk.idca", name = "trust-certificate")
    public IdcaChainVerifier idcaChainVerifier(AtiSdkProperties props) {
        return new IdcaChainVerifier(props.getIdca().getTrustCertificate());
    }

    @Bean
    public DefaultConnectionVerifier defaultConnectionVerifier(
            DaneTlsaVerifier daneVerifier,
            BadgeVerifier badgeVerifier) {
        return new DefaultConnectionVerifier(daneVerifier, badgeVerifier);
    }

    @Bean
    public AtiVerifiedClient atiVerifiedClient(
            AtiDiscoveryClient discoveryClient,
            DefaultConnectionVerifier verifier,
            AtiSdkProperties props) {
        return AtiVerifiedClient.builder()
            .discoveryClient(discoveryClient)
            .connectionVerifier(verifier)
            .identityCertificatePath(props.getIdentity().getCertificate())
            .identityPrivateKeyPath(props.getIdentity().getPrivateKey())
            .defaultPolicy(parsePolicy(props.getVerification().getPolicy()))
            .build();
    }

    private static VerificationPolicy parsePolicy(String name) {
        try {
            return VerificationPolicy.valueOf(name.toUpperCase());
        } catch (IllegalArgumentException e) {
            throw new IllegalArgumentException(
                "Unknown verification policy: " + name
                    + ". Expected: BRONZE, SILVER, or GOLD");
        }
    }
}
