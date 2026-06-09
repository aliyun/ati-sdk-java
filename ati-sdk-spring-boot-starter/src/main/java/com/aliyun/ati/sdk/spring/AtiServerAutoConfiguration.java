package com.aliyun.ati.sdk.spring;

import java.net.http.HttpClient;
import java.time.Duration;

import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnExpression;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.server.Ssl;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.boot.web.servlet.server.ConfigurableServletWebServerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import com.aliyun.ati.sdk.agent.server.ClientRequestVerifier;
import com.aliyun.ati.sdk.transparency.AtiTransparencyClient;
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
    @ConditionalOnMissingBean
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
    @ConditionalOnMissingBean
    public TlSealVerifier tlSealVerifier() {
        return new TlSealVerifier();
    }

    @Bean
    @ConditionalOnMissingBean
    public MerkleProofVerifier merkleProofVerifier() {
        return new MerkleProofVerifier();
    }

    @Bean
    @ConditionalOnMissingBean
    public BadgeVerificationService badgeVerificationService(
            AtiTransparencyClient client,
            TlSealVerifier sealVerifier,
            MerkleProofVerifier merkleVerifier) {
        return new BadgeVerificationService(
            client, sealVerifier, merkleVerifier);
    }

    @Bean
    @ConditionalOnMissingBean
    public CachingBadgeVerificationService cachingBadgeVerificationService(
            BadgeVerificationService service) {
        return new CachingBadgeVerificationService(service);
    }

    @Bean
    public ClientRequestVerifier clientRequestVerifier(
            CachingBadgeVerificationService service) {
        return new ClientRequestVerifier(service);
    }

    @Bean
    @ConditionalOnClass(ConfigurableServletWebServerFactory.class)
    public WebServerFactoryCustomizer<ConfigurableServletWebServerFactory>
            atiServerSslCustomizer(AtiSdkProperties props) {
        return factory -> {
            AtiSdkProperties.Server serverProps = props.getServer();
            if (serverProps.getCertificate() == null) {
                return;
            }
            Ssl ssl = new Ssl();
            ssl.setCertificate(serverProps.getCertificate());
            ssl.setCertificatePrivateKey(serverProps.getPrivateKey());
            if (props.getIdca().getTrustCertificate() != null) {
                ssl.setTrustCertificate(
                    props.getIdca().getTrustCertificate());
                ssl.setClientAuth(Ssl.ClientAuth.NEED);
            }
            factory.setSsl(ssl);
        };
    }
}
