package com.aliyun.ati.sdk.agent.http;

import com.aliyun.ati.sdk.agent.VerificationPolicy;
import com.aliyun.ati.sdk.agent.verification.ConnectionVerifier;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.net.http.HttpClient;
import java.time.Duration;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

/**
 * Tests for AtiHttpClient.
 */
class AtiHttpClientTest {

    private HttpClient mockHttpClient;
    private ConnectionVerifier mockVerifier;
    private CapturedCertificateProvider mockCertProvider;

    @BeforeEach
    void setUp() {
        mockHttpClient = mock(HttpClient.class);
        mockVerifier = mock(ConnectionVerifier.class);
        mockCertProvider = mock(CapturedCertificateProvider.class);
    }

    @Test
    void builderCreatesClient() {
        AtiHttpClient client = AtiHttpClient.builder()
            .delegate(mockHttpClient)
            .connectionVerifier(mockVerifier)
            .verificationPolicy(VerificationPolicy.BASIC)
            .build();

        assertNotNull(client);
        assertSame(mockHttpClient, client.getDelegate());
    }

    @Test
    void builderRequiresDelegate() {
        assertThrows(NullPointerException.class, () ->
            AtiHttpClient.builder()
                .connectionVerifier(mockVerifier)
                .verificationPolicy(VerificationPolicy.BASIC)
                .build());
    }

    @Test
    void builderRequiresVerifier() {
        assertThrows(NullPointerException.class, () ->
            AtiHttpClient.builder()
                .delegate(mockHttpClient)
                .verificationPolicy(VerificationPolicy.BASIC)
                .build());
    }

    @Test
    void builderRequiresPolicy() {
        assertThrows(NullPointerException.class, () ->
            AtiHttpClient.builder()
                .delegate(mockHttpClient)
                .connectionVerifier(mockVerifier)
                .build());
    }

    @Test
    void builderAcceptsPreVerifyTimeout() {
        AtiHttpClient client = AtiHttpClient.builder()
            .delegate(mockHttpClient)
            .connectionVerifier(mockVerifier)
            .verificationPolicy(VerificationPolicy.ADVANCED)
            .preVerifyTimeout(Duration.ofSeconds(30))
            .build();

        assertNotNull(client);
    }

    @Test
    void noVerificationCreatesWorkingClient() {
        AtiHttpClient client = AtiHttpClient.noVerification(mockHttpClient);

        assertNotNull(client);
        assertSame(mockHttpClient, client.getDelegate());
    }

    @Test
    void noVerificationRequiresHttpClient() {
        assertThrows(NullPointerException.class, () ->
            AtiHttpClient.noVerification(null));
    }

    @Test
    void clearCacheDoesNotThrow() {
        AtiHttpClient client = AtiHttpClient.builder()
            .delegate(mockHttpClient)
            .connectionVerifier(mockVerifier)
            .verificationPolicy(VerificationPolicy.BASIC)
            .build();

        client.clearCache();
        // Should not throw
    }

    @Test
    void invalidateCacheDoesNotThrow() {
        AtiHttpClient client = AtiHttpClient.builder()
            .delegate(mockHttpClient)
            .connectionVerifier(mockVerifier)
            .verificationPolicy(VerificationPolicy.BASIC)
            .build();

        client.invalidateCache("example.com", 443);
        // Should not throw
    }

    @Test
    void builderMethodsReturnBuilder() {
        AtiHttpClient.Builder builder = AtiHttpClient.builder();

        assertSame(builder, builder.delegate(mockHttpClient));
        assertSame(builder, builder.connectionVerifier(mockVerifier));
        assertSame(builder, builder.verificationPolicy(VerificationPolicy.BASIC));
        assertSame(builder, builder.preVerifyTimeout(Duration.ofSeconds(5)));
        assertSame(builder, builder.certProvider(mockCertProvider));
    }

    @Test
    void noVerificationClientGetDelegate() {
        AtiHttpClient client = AtiHttpClient.noVerification(mockHttpClient);
        assertEquals(mockHttpClient, client.getDelegate());
    }

}
