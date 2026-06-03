package com.aliyun.ati.sdk.transparency.verification;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class CachingBadgeVerificationServiceTest {

    private BadgeVerificationService delegate;
    private CachingBadgeVerificationService cachingService;

    @BeforeEach
    void setUp() {
        delegate = mock(BadgeVerificationService.class);
        cachingService = new CachingBadgeVerificationService(delegate);
    }

    @Test
    void shouldCacheServerVerificationResult() {
        ServerVerificationResult result =
            ServerVerificationResult.verified("SHA-256:abc", "agent-1");
        when(delegate.verifyServer("agent-1")).thenReturn(result);

        ServerVerificationResult first = cachingService.verifyServer("agent-1");
        ServerVerificationResult second = cachingService.verifyServer("agent-1");

        assertThat(first.getStatus()).isEqualTo(VerificationStatus.VERIFIED);
        assertThat(second.getStatus()).isEqualTo(VerificationStatus.VERIFIED);
        verify(delegate, times(1)).verifyServer("agent-1");
    }

    @Test
    void shouldCacheClientVerificationResult() {
        ClientVerificationResult result =
            ClientVerificationResult.verified(
                "SHA-256:xyz", "agent.example.com", "agent-1");
        when(delegate.verifyClient("agent-1")).thenReturn(result);

        ClientVerificationResult first = cachingService.verifyClient("agent-1");
        ClientVerificationResult second = cachingService.verifyClient("agent-1");

        assertThat(first.getStatus()).isEqualTo(VerificationStatus.VERIFIED);
        assertThat(second.getStatus()).isEqualTo(VerificationStatus.VERIFIED);
        verify(delegate, times(1)).verifyClient("agent-1");
    }

    @Test
    void shouldCacheNegativeResult() {
        ServerVerificationResult result =
            ServerVerificationResult.failed(
                VerificationStatus.AGENT_REVOKED, "agent-2");
        when(delegate.verifyServer("agent-2")).thenReturn(result);

        cachingService.verifyServer("agent-2");
        cachingService.verifyServer("agent-2");

        verify(delegate, times(1)).verifyServer("agent-2");
    }

    @Test
    void shouldNotShareCacheBetweenAgents() {
        ServerVerificationResult r1 =
            ServerVerificationResult.verified("SHA-256:aaa", "agent-1");
        ServerVerificationResult r2 =
            ServerVerificationResult.verified("SHA-256:bbb", "agent-2");
        when(delegate.verifyServer("agent-1")).thenReturn(r1);
        when(delegate.verifyServer("agent-2")).thenReturn(r2);

        assertThat(cachingService.verifyServer("agent-1")
            .getServerCertFingerprint()).isEqualTo("SHA-256:aaa");
        assertThat(cachingService.verifyServer("agent-2")
            .getServerCertFingerprint()).isEqualTo("SHA-256:bbb");
    }
}
