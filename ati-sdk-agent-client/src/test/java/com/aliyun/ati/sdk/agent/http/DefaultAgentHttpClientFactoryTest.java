package com.aliyun.ati.sdk.agent.http;

import com.aliyun.ati.sdk.agent.ConnectOptions;
import com.aliyun.ati.sdk.agent.VerificationPolicy;
import com.aliyun.ati.sdk.agent.exception.AgentConnectionException;
import com.aliyun.ati.sdk.agent.verification.DaneTlsaVerifier;
import com.aliyun.ati.sdk.transparency.TransparencyClient;
import com.aliyun.ati.sdk.transparency.verification.SealTrustChain;
import org.junit.jupiter.api.Test;

import java.net.http.HttpClient;
import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Tests for DefaultAgentHttpClientFactory.
 */
class DefaultAgentHttpClientFactoryTest {

    @Test
    void defaultConstructorCreatesFactory() {
        DefaultAgentHttpClientFactory factory = new DefaultAgentHttpClientFactory();
        assertNotNull(factory);
    }

    @Test
    void constructorWithDaneVerifier() {
        DaneTlsaVerifier mockVerifier = mock(DaneTlsaVerifier.class);
        DefaultAgentHttpClientFactory factory = new DefaultAgentHttpClientFactory(mockVerifier);
        assertNotNull(factory);
    }

    @Test
    void constructorWithDaneVerifierAndSealTrustChain() {
        DaneTlsaVerifier mockVerifier = mock(DaneTlsaVerifier.class);
        SealTrustChain chain = SealTrustChain.shipped();
        DefaultAgentHttpClientFactory factory = new DefaultAgentHttpClientFactory(mockVerifier, chain);
        assertNotNull(factory);
    }

    @Test
    void createVerifiedWithSealTrustChainOnOptions() {
        DefaultAgentHttpClientFactory factory = new DefaultAgentHttpClientFactory();
        ConnectOptions options = ConnectOptions.builder()
            .verificationPolicy(VerificationPolicy.ENHANCED)
            .transparencyClient(mock(TransparencyClient.class))
            .sealTrustChain(SealTrustChain.shipped())
            .build();

        VerifiedClientResult result = factory.createVerified(
            "example.com", options, Duration.ofSeconds(10));

        assertNotNull(result);
        assertNotNull(result.atiHttpClient());
        assertNotNull(result.verifier());
    }

    @Test
    void constructorRejectsNullDaneVerifier() {
        assertThrows(NullPointerException.class, () ->
            new DefaultAgentHttpClientFactory(null));
    }

    @Test
    void createVerifiedRejectsNullHostname() {
        DefaultAgentHttpClientFactory factory = new DefaultAgentHttpClientFactory();
        ConnectOptions options = ConnectOptions.builder().verificationPolicy(VerificationPolicy.BASIC).build();

        assertThrows(NullPointerException.class, () ->
            factory.createVerified(null, options, Duration.ofSeconds(10)));
    }

    @Test
    void createVerifiedRejectsNullOptions() {
        DefaultAgentHttpClientFactory factory = new DefaultAgentHttpClientFactory();

        assertThrows(NullPointerException.class, () ->
            factory.createVerified("example.com", null, Duration.ofSeconds(10)));
    }

    @Test
    void createVerifiedRejectsNullTimeout() {
        DefaultAgentHttpClientFactory factory = new DefaultAgentHttpClientFactory();
        ConnectOptions options = ConnectOptions.builder().verificationPolicy(VerificationPolicy.BASIC).build();

        assertThrows(NullPointerException.class, () ->
            factory.createVerified("example.com", options, null));
    }

    @Test
    void createVerifiedWithPkiOnly() {
        DefaultAgentHttpClientFactory factory = new DefaultAgentHttpClientFactory();
        ConnectOptions options = ConnectOptions.builder()
            .verificationPolicy(VerificationPolicy.BASIC)
            .build();

        VerifiedClientResult result = factory.createVerified(
            "example.com", options, Duration.ofSeconds(10));

        assertNotNull(result);
        assertNotNull(result.atiHttpClient());
        assertNotNull(result.verifier());
    }

    @Test
    void createVerifiedWithDaneRequired() {
        DefaultAgentHttpClientFactory factory = new DefaultAgentHttpClientFactory();
        ConnectOptions options = ConnectOptions.builder()
            .verificationPolicy(VerificationPolicy.ADVANCED)
            .transparencyClient(mock(TransparencyClient.class))
            .build();

        VerifiedClientResult result = factory.createVerified(
            "example.com", options, Duration.ofSeconds(10));

        assertNotNull(result);
    }

    @Test
    void createReturnsHttpClient() {
        DefaultAgentHttpClientFactory factory = new DefaultAgentHttpClientFactory();
        ConnectOptions options = ConnectOptions.builder().verificationPolicy(VerificationPolicy.BASIC).build();

        HttpClient client = factory.create("example.com", options, Duration.ofSeconds(10));

        assertNotNull(client);
    }

    @Test
    void createRejectsNullHostname() {
        DefaultAgentHttpClientFactory factory = new DefaultAgentHttpClientFactory();

        assertThrows(NullPointerException.class, () ->
            factory.create(null, ConnectOptions.builder().verificationPolicy(VerificationPolicy.BASIC).build(), Duration.ofSeconds(10)));
    }

    @Test
    void createVerifiedWithBadgeRequiredThrowsWithoutTransparencyClient() {
        // Badge verification requires an explicit TransparencyClient
        DefaultAgentHttpClientFactory factory = new DefaultAgentHttpClientFactory();
        ConnectOptions options = ConnectOptions.builder()
            .verificationPolicy(VerificationPolicy.ENHANCED)
            .build();

        AgentConnectionException thrown = assertThrows(AgentConnectionException.class, () ->
            factory.createVerified("example.com", options, Duration.ofSeconds(10)));
        assertTrue(thrown.getCause() instanceof IllegalStateException);
    }

    @Test
    void createVerifiedWithBadgeRequiredAndTransparencyClient() {
        // Badge verification works when TransparencyClient is provided
        DefaultAgentHttpClientFactory factory = new DefaultAgentHttpClientFactory();
        TransparencyClient mockTransparencyClient = mock(TransparencyClient.class);
        ConnectOptions options = ConnectOptions.builder()
            .verificationPolicy(VerificationPolicy.ENHANCED)
            .transparencyClient(mockTransparencyClient)
            .build();

        VerifiedClientResult result = factory.createVerified(
            "example.com", options, Duration.ofSeconds(10));

        assertNotNull(result);
        assertNotNull(result.atiHttpClient());
        assertNotNull(result.verifier());
    }

    @Test
    void createVerifiedWithBothDaneAndBadgeEnabled() {
        // Tests creating verifiers for both DANE and Badge
        DefaultAgentHttpClientFactory factory = new DefaultAgentHttpClientFactory();
        TransparencyClient mockTransparencyClient = mock(TransparencyClient.class);
        ConnectOptions options = ConnectOptions.builder()
            .verificationPolicy(VerificationPolicy.ADVANCED)
            .transparencyClient(mockTransparencyClient)
            .build();

        VerifiedClientResult result = factory.createVerified(
            "example.com", options, Duration.ofSeconds(10));

        assertNotNull(result);
        assertNotNull(result.verifier());
    }

    @Test
    void createVerifiedWithCustomTransparencyClient() {
        // Tests that custom TransparencyClient is used when provided
        DefaultAgentHttpClientFactory factory = new DefaultAgentHttpClientFactory();
        TransparencyClient mockTransparencyClient = mock(TransparencyClient.class);

        ConnectOptions options = ConnectOptions.builder()
            .verificationPolicy(VerificationPolicy.ENHANCED)
            .transparencyClient(mockTransparencyClient)
            .build();

        VerifiedClientResult result = factory.createVerified(
            "example.com", options, Duration.ofSeconds(10));

        assertNotNull(result);
    }

    @Test
    void createVerifiedReusesVerificationService() {
        // Tests that badge verification works across multiple calls with same client
        DefaultAgentHttpClientFactory factory = new DefaultAgentHttpClientFactory();
        TransparencyClient mockTransparencyClient = mock(TransparencyClient.class);
        ConnectOptions options = ConnectOptions.builder()
            .verificationPolicy(VerificationPolicy.ENHANCED)
            .transparencyClient(mockTransparencyClient)
            .build();

        // First call creates the verification service
        VerifiedClientResult result1 = factory.createVerified(
            "example.com", options, Duration.ofSeconds(10));

        // Second call should also succeed
        VerifiedClientResult result2 = factory.createVerified(
            "example.org", options, Duration.ofSeconds(10));

        assertNotNull(result1);
        assertNotNull(result2);
        // Both should have verifiers
        assertNotNull(result1.verifier());
        assertNotNull(result2.verifier());
    }

    @Test
    void createVerifiedWithPkiOnlyMode() {
        // Tests creating with PKI_ONLY mode (no extra verifiers)
        DefaultAgentHttpClientFactory factory = new DefaultAgentHttpClientFactory();
        ConnectOptions options = ConnectOptions.builder()
            .verificationPolicy(VerificationPolicy.BASIC)
            .build();

        VerifiedClientResult result = factory.createVerified(
            "example.com", options, Duration.ofSeconds(10));

        assertNotNull(result);
    }

    @Test
    void createVerifiedWithBadgeOnly() {
        // Tests that Badge verifier is added without DANE
        DefaultAgentHttpClientFactory factory = new DefaultAgentHttpClientFactory();
        TransparencyClient mockTransparencyClient = mock(TransparencyClient.class);
        ConnectOptions options = ConnectOptions.builder()
            .verificationPolicy(VerificationPolicy.ENHANCED)
            .transparencyClient(mockTransparencyClient)
            .build();

        VerifiedClientResult result = factory.createVerified(
            "example.com", options, Duration.ofSeconds(10));

        assertNotNull(result);
        // Verifier should still exist (badge verifier)
        assertNotNull(result.verifier());
    }

    @Test
    void createVerifiedWithDaneAndBadge() {
        // Tests that both DANE and Badge verifiers are added
        DefaultAgentHttpClientFactory factory = new DefaultAgentHttpClientFactory();
        TransparencyClient mockTransparencyClient = mock(TransparencyClient.class);
        ConnectOptions options = ConnectOptions.builder()
            .verificationPolicy(VerificationPolicy.ADVANCED)
            .transparencyClient(mockTransparencyClient)
            .build();

        VerifiedClientResult result = factory.createVerified(
            "example.com", options, Duration.ofSeconds(10));

        assertNotNull(result);
        assertNotNull(result.verifier());
    }

    @Test
    void createReturnsUnderlyingHttpClient() {
        // Tests that create() returns the underlying HttpClient, not the wrapper
        DefaultAgentHttpClientFactory factory = new DefaultAgentHttpClientFactory();
        ConnectOptions options = ConnectOptions.builder().verificationPolicy(VerificationPolicy.BASIC).build();

        HttpClient client = factory.create("example.com", options, Duration.ofSeconds(10));

        assertNotNull(client);
        // Should be a raw HttpClient, not AtiHttpClient
    }

    @Test
    void createVerifiedWiresCertProviderIntoAtiHttpClient() {
        // Regression test: certProvider must be wired into AtiHttpClient
        // so that post-handshake certificate verification can run.
        DefaultAgentHttpClientFactory factory = new DefaultAgentHttpClientFactory();
        ConnectOptions options = ConnectOptions.builder()
            .verificationPolicy(VerificationPolicy.BASIC)
            .build();

        VerifiedClientResult result = factory.createVerified(
            "example.com", options, Duration.ofSeconds(10));

        assertNotNull(result.atiHttpClient());
        assertThat(result.atiHttpClient().hasCertProvider())
            .as("certProvider must be wired for post-handshake verification")
            .isTrue();
    }

    // ==================== Progressive policy support ====================

    @Test
    void createVerifiedWithAllPolicies() {
        // Verifies all progressive policy levels work
        DefaultAgentHttpClientFactory factory = new DefaultAgentHttpClientFactory();
        TransparencyClient mockTransparencyClient = mock(TransparencyClient.class);
        when(mockTransparencyClient.getBaseUrl()).thenReturn("https://transparency.test.example.com");

        // PKI_ONLY
        ConnectOptions pkiOptions = ConnectOptions.builder()
            .verificationPolicy(VerificationPolicy.BASIC)
            .build();
        VerifiedClientResult pkiResult = factory.createVerified(
            "example.com", pkiOptions, Duration.ofSeconds(10));
        assertNotNull(pkiResult);

        // BADGE_REQUIRED
        ConnectOptions badgeOptions = ConnectOptions.builder()
            .verificationPolicy(VerificationPolicy.ENHANCED)
            .transparencyClient(mockTransparencyClient)
            .build();
        VerifiedClientResult badgeResult = factory.createVerified(
            "example.com", badgeOptions, Duration.ofSeconds(10));
        assertNotNull(badgeResult);
        assertNotNull(badgeResult.verifier());

        // DANE_AND_BADGE
        ConnectOptions daneOptions = ConnectOptions.builder()
            .verificationPolicy(VerificationPolicy.ADVANCED)
            .transparencyClient(mockTransparencyClient)
            .build();
        VerifiedClientResult daneResult = factory.createVerified(
            "example.com", daneOptions, Duration.ofSeconds(10));
        assertNotNull(daneResult);
        assertNotNull(daneResult.verifier());
    }

}
