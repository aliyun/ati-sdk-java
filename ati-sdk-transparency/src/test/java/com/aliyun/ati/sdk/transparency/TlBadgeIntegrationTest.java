package com.aliyun.ati.sdk.transparency;

import java.net.Socket;
import java.net.http.HttpClient;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509ExtendedTrustManager;

import com.aliyun.ati.sdk.transparency.model.MerkleProof;
import com.aliyun.ati.sdk.transparency.model.Seal;
import com.aliyun.ati.sdk.transparency.model.TransparencyLogResponse;
import com.aliyun.ati.sdk.transparency.verification.BadgeVerificationService;
import com.aliyun.ati.sdk.transparency.verification.MerkleProofVerifier;
import com.aliyun.ati.sdk.transparency.verification.ServerVerificationResult;
import com.aliyun.ati.sdk.transparency.verification.TlSealVerifier;
import com.aliyun.ati.sdk.transparency.verification.VerificationStatus;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.condition.EnabledIfEnvironmentVariable;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Integration test that connects to the CNNIC Transparency Log test endpoint
 * to verify the full Badge verification flow: TL fetch + seal signature
 * verification + Merkle inclusion proof verification.
 *
 * <p>Guarded by the {@code ATI_TL_INTEGRATION_TEST} environment variable so it
 * only runs when explicitly enabled:
 * <pre>
 *   ATI_TL_INTEGRATION_TEST=true gradle :ati-sdk-transparency:test \
 *       --tests "*TlBadgeIntegrationTest*"
 * </pre>
 */
@EnabledIfEnvironmentVariable(named = "ATI_TL_INTEGRATION_TEST", matches = "true")
class TlBadgeIntegrationTest {

    private static final String TL_BASE_URL =
        "https://42.83.147.217:8180/ans/api/v1";
    private static final String TEST_AGENT_ID =
        "effae2b2-f451-4c1c-addd-212c649ef5bd";

    private static AtiTransparencyClient transparencyClient;

    @BeforeAll
    static void setUp() throws Exception {
        SSLContext sslContext = SSLContext.getInstance("TLS");
        sslContext.init(null, new TrustManager[]{new TrustAllManager()},
            new SecureRandom());
        SSLParameters sslParams = new SSLParameters();
        sslParams.setEndpointIdentificationAlgorithm("");
        HttpClient httpClient = HttpClient.newBuilder()
            .sslContext(sslContext)
            .sslParameters(sslParams)
            .connectTimeout(java.time.Duration.ofSeconds(10))
            .build();
        transparencyClient = new AtiTransparencyClient(TL_BASE_URL, httpClient);
    }

    @Test
    void shouldFetchLatestLogFromTlEndpoint() {
        TransparencyLogResponse response =
            transparencyClient.getLatestLog(TEST_AGENT_ID);

        assertThat(response).isNotNull();
        assertThat(response.getStatus()).isEqualTo("ACTIVE");
        assertThat(response.getSchemaVersion()).isNotNull();

        // Payload
        assertThat(response.getPayload()).isNotNull();
        assertThat(response.getPayload().getAgentId())
            .isEqualTo(TEST_AGENT_ID);
        assertThat(response.getPayload().getCertificates()).isNotNull();
        assertThat(response.getPayload().getCertificates()
            .getServerCertFingerprint())
            .isNotNull()
            .isNotEmpty();

        // Seal
        Seal seal = response.getSeal();
        assertThat(seal).isNotNull();
        assertThat(seal.getSignature()).isNotNull().isNotEmpty();
        assertThat(seal.getPublicKey()).isNotNull().isNotEmpty();

        // Merkle proof
        MerkleProof proof = response.getMerkleProof();
        assertThat(proof).isNotNull();
        assertThat(proof.getLeafHash()).isNotNull().isNotEmpty();
        assertThat(proof.getRootHash()).isNotNull().isNotEmpty();
        assertThat(proof.getPath()).isNotNull();
    }

    @Test
    void shouldPassFullBadgeVerification() {
        BadgeVerificationService service = new BadgeVerificationService(
            transparencyClient,
            new TlSealVerifier(),
            new MerkleProofVerifier());

        ServerVerificationResult result = service.verifyServer(TEST_AGENT_ID);

        assertThat(result.getStatus())
            .as("Badge verification should succeed — seal + merkle + ACTIVE")
            .isEqualTo(VerificationStatus.VERIFIED);
        assertThat(result.getServerCertFingerprint())
            .isNotNull()
            .isNotEmpty();
        assertThat(result.getAgentId()).isEqualTo(TEST_AGENT_ID);
    }

    /**
     * Extended trust manager that accepts all certificates and skips
     * hostname verification — only for integration tests against the
     * CNNIC test endpoint which uses an IP address with a non-standard
     * certificate.
     *
     * <p>Extends {@link X509ExtendedTrustManager} so that the JDK TLS
     * implementation uses it directly without wrapping (the wrapper
     * would re-introduce hostname checking via {@code HostnameChecker}).
     */
    private static final class TrustAllManager
            extends X509ExtendedTrustManager {
        @Override
        public void checkClientTrusted(X509Certificate[] chain,
                                        String authType) {
            // no-op
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain,
                                        String authType) {
            // no-op
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain,
                                        String authType, Socket socket) {
            // no-op
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain,
                                        String authType, Socket socket) {
            // no-op
        }

        @Override
        public void checkClientTrusted(X509Certificate[] chain,
                                        String authType, SSLEngine engine) {
            // no-op
        }

        @Override
        public void checkServerTrusted(X509Certificate[] chain,
                                        String authType, SSLEngine engine) {
            // no-op
        }

        @Override
        public X509Certificate[] getAcceptedIssuers() {
            return new X509Certificate[0];
        }
    }
}
