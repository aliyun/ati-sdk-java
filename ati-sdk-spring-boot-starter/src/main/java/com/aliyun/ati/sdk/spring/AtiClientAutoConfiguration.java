package com.aliyun.ati.sdk.spring;

import java.net.http.HttpClient;

import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.aliyun.ati.sdk.agent.AtiVerifiedClient;
import com.aliyun.ati.sdk.agent.verification.BadgeVerifier;
import com.aliyun.ati.sdk.agent.verification.DaneTlsaVerifier;
import com.aliyun.ati.sdk.agent.verification.DefaultConnectionVerifier;
import com.aliyun.ati.sdk.discovery.AtiDiscoveryClient;
import com.aliyun.ati.sdk.discovery.DnsAtiDiscoveryClient;
import com.aliyun.ati.sdk.transparency.AtiTransparencyClient;
import com.aliyun.ati.sdk.transparency.RootKeyManager;
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
        return new AtiTransparencyClient(
            props.getTransparency().getBaseUrl(),
            HttpClient.newHttpClient());
    }

    @Bean
    public RootKeyManager rootKeyManager(
            AtiTransparencyClient transparencyClient) {
        return new RootKeyManager(transparencyClient);
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
            RootKeyManager rootKeyManager,
            TlSealVerifier sealVerifier,
            MerkleProofVerifier merkleVerifier) {
        return new BadgeVerificationService(
            client, rootKeyManager, sealVerifier, merkleVerifier);
    }

    @Bean
    public CachingBadgeVerificationService cachingBadgeVerificationService(
            BadgeVerificationService service) {
        return new CachingBadgeVerificationService(service);
    }

    @Bean
    public AtiDiscoveryClient atiDiscoveryClient() {
        return new DnsAtiDiscoveryClient();
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
    public DefaultConnectionVerifier defaultConnectionVerifier(
            DaneTlsaVerifier daneVerifier,
            BadgeVerifier badgeVerifier) {
        return new DefaultConnectionVerifier(daneVerifier, badgeVerifier);
    }

    @Bean
    public AtiVerifiedClient atiVerifiedClient(
            AtiDiscoveryClient discoveryClient,
            DefaultConnectionVerifier verifier) {
        return AtiVerifiedClient.builder()
            .discoveryClient(discoveryClient)
            .connectionVerifier(verifier)
            .build();
    }
}
