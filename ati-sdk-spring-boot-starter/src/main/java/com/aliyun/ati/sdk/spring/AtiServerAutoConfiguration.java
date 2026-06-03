package com.aliyun.ati.sdk.spring;

import java.net.http.HttpClient;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.aliyun.ati.sdk.agent.server.ClientRequestVerifier;
import com.aliyun.ati.sdk.agent.verification.IdcaChainVerifier;
import com.aliyun.ati.sdk.transparency.AtiTransparencyClient;
import com.aliyun.ati.sdk.transparency.RootKeyManager;
import com.aliyun.ati.sdk.transparency.verification.BadgeVerificationService;
import com.aliyun.ati.sdk.transparency.verification.CachingBadgeVerificationService;
import com.aliyun.ati.sdk.transparency.verification.MerkleProofVerifier;
import com.aliyun.ati.sdk.transparency.verification.TlSealVerifier;

/**
 * Auto-configuration for ATI SDK server beans.
 *
 * <p>Activates when {@code ati.sdk.mode} is "server" or "both".
 * Registers Transparency Log beans and the {@link ClientRequestVerifier}
 * for verifying inbound client mTLS certificates.
 */
@Configuration
@ConditionalOnExpression(
    "'${ati.sdk.mode:client}' == 'server' "
        + "or '${ati.sdk.mode:client}' == 'both'"
)
@EnableConfigurationProperties(AtiSdkProperties.class)
public class AtiServerAutoConfiguration {

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
    @ConditionalOnProperty(prefix = "ati.sdk.idca", name = "trust-certificate")
    @ConditionalOnMissingBean
    public IdcaChainVerifier idcaChainVerifier(AtiSdkProperties props) {
        return new IdcaChainVerifier(props.getIdca().getTrustCertificate());
    }

    @Bean
    public ClientRequestVerifier clientRequestVerifier(
            CachingBadgeVerificationService service,
            @Autowired(required = false) IdcaChainVerifier idcaVerifier) {
        return new ClientRequestVerifier(service, idcaVerifier);
    }
}
