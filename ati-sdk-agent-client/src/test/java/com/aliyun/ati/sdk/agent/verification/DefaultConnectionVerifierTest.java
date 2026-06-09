package com.aliyun.ati.sdk.agent.verification;

import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

import com.aliyun.ati.sdk.agent.VerificationPolicy;
import com.aliyun.ati.sdk.discovery.AtiAgentDescriptor;
import com.aliyun.ati.sdk.transparency.verification.ServerVerificationResult;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class DefaultConnectionVerifierTest {

    private DaneTlsaVerifier daneVerifier;
    private BadgeVerifier badgeVerifier;
    private DefaultConnectionVerifier verifier;
    private X509Certificate serverCert;

    @BeforeEach
    void setUp() {
        daneVerifier = mock(DaneTlsaVerifier.class);
        badgeVerifier = mock(BadgeVerifier.class);
        verifier = new DefaultConnectionVerifier(daneVerifier, badgeVerifier);
        serverCert = mock(X509Certificate.class);
    }

    // --- preVerify tests ---

    @Test
    void preVerifyBronzeShouldSkipAll() {
        AtiAgentDescriptor descriptor = new AtiAgentDescriptor(
            "example.com", "v1", null, "agent-001");

        PreVerificationResult result =
            verifier.preVerify(descriptor, VerificationPolicy.BRONZE, 443);

        assertThat(result.getDaneExpectations()).isEmpty();
        assertThat(result.getBadgeResult()).isNull();
        verify(daneVerifier, never()).getTlsaExpectations(anyString(), anyInt());
        verify(badgeVerifier, never()).preVerify(anyString());
    }

    @Test
    void preVerifySilverShouldQueryDaneOnly() {
        AtiAgentDescriptor descriptor = new AtiAgentDescriptor(
            "example.com", "v1", null, "agent-001");

        List<DaneTlsaVerifier.TlsaExpectation> expectations =
            List.of(new DaneTlsaVerifier.TlsaExpectation(1, 1, new byte[32]));
        when(daneVerifier.getTlsaExpectations("example.com", 443))
            .thenReturn(expectations);

        PreVerificationResult result =
            verifier.preVerify(descriptor, VerificationPolicy.SILVER, 443);

        assertThat(result.getDaneExpectations()).hasSize(1);
        assertThat(result.getBadgeResult()).isNull();
        verify(badgeVerifier, never()).preVerify(anyString());
    }

    @Test
    void preVerifyGoldShouldQueryDaneAndBadge() {
        AtiAgentDescriptor descriptor = new AtiAgentDescriptor(
            "example.com", "v1", null, "agent-001");

        List<DaneTlsaVerifier.TlsaExpectation> expectations =
            List.of(new DaneTlsaVerifier.TlsaExpectation(1, 1, new byte[32]));
        when(daneVerifier.getTlsaExpectations("example.com", 443))
            .thenReturn(expectations);

        ServerVerificationResult badgeResult =
            ServerVerificationResult.verified("SHA-256:abc", "agent-001");
        when(badgeVerifier.preVerify("agent-001")).thenReturn(badgeResult);

        PreVerificationResult result =
            verifier.preVerify(descriptor, VerificationPolicy.GOLD, 443);

        assertThat(result.getDaneExpectations()).hasSize(1);
        assertThat(result.getBadgeResult()).isSameAs(badgeResult);
        assertThat(result.getPolicy()).isEqualTo(VerificationPolicy.GOLD);
    }

    @Test
    void preVerifyGoldShouldSkipBadgeWhenAgentIdNull() {
        AtiAgentDescriptor descriptor = new AtiAgentDescriptor(
            "example.com", "v1", null, null);

        when(daneVerifier.getTlsaExpectations("example.com", 443))
            .thenReturn(Collections.emptyList());

        PreVerificationResult result =
            verifier.preVerify(descriptor, VerificationPolicy.GOLD, 443);

        assertThat(result.getBadgeResult()).isNull();
        verify(badgeVerifier, never()).preVerify(anyString());
    }

    @Test
    void preVerifyShouldHandleDaneException() {
        AtiAgentDescriptor descriptor = new AtiAgentDescriptor(
            "example.com", "v1", null, null);

        when(daneVerifier.getTlsaExpectations("example.com", 443))
            .thenThrow(new RuntimeException("DNS failure"));

        PreVerificationResult result =
            verifier.preVerify(descriptor, VerificationPolicy.SILVER, 443);

        assertThat(result.getDaneExpectations()).isEmpty();
    }

    @Test
    void preVerifyShouldHandleBadgeException() {
        AtiAgentDescriptor descriptor = new AtiAgentDescriptor(
            "example.com", "v1", null, "agent-001");

        when(daneVerifier.getTlsaExpectations("example.com", 443))
            .thenReturn(Collections.emptyList());
        when(badgeVerifier.preVerify("agent-001"))
            .thenThrow(new RuntimeException("TL failure"));

        PreVerificationResult result =
            verifier.preVerify(descriptor, VerificationPolicy.GOLD, 443);

        assertThat(result.getBadgeResult()).isNull();
    }

    // --- postVerify tests ---

    @Test
    void postVerifyGoldShouldRunDaneAndBadge() {
        List<DaneTlsaVerifier.TlsaExpectation> expectations =
            List.of(new DaneTlsaVerifier.TlsaExpectation(1, 1, new byte[32]));
        ServerVerificationResult badgeResult =
            ServerVerificationResult.verified("SHA-256:abc", "agent-001");

        AtiAgentDescriptor descriptor = new AtiAgentDescriptor(
            "example.com", "v1", null, "agent-001");
        PreVerificationResult preResult = new PreVerificationResult(
            descriptor, VerificationPolicy.GOLD, expectations, badgeResult);

        when(daneVerifier.postVerify(serverCert, expectations))
            .thenReturn(VerificationResult.success(VerificationResult.Type.DANE));
        when(badgeVerifier.postVerify(serverCert, badgeResult))
            .thenReturn(VerificationResult.success(VerificationResult.Type.BADGE));

        List<VerificationResult> results =
            verifier.postVerify(serverCert, preResult);

        assertThat(results).hasSize(2);
        assertThat(results.get(0).getType()).isEqualTo(VerificationResult.Type.DANE);
        assertThat(results.get(1).getType()).isEqualTo(VerificationResult.Type.BADGE);
    }

    @Test
    void postVerifyBronzeShouldSkipAll() {
        AtiAgentDescriptor descriptor = new AtiAgentDescriptor(
            "example.com", "v1", null, "agent-001");
        PreVerificationResult preResult = new PreVerificationResult(
            descriptor, VerificationPolicy.BRONZE,
            Collections.emptyList(), null);

        List<VerificationResult> results =
            verifier.postVerify(serverCert, preResult);

        assertThat(results).isEmpty();
    }

    @Test
    void postVerifyShouldReturnFailureWithoutThrowing() {
        List<DaneTlsaVerifier.TlsaExpectation> expectations =
            List.of(new DaneTlsaVerifier.TlsaExpectation(1, 1, new byte[32]));
        AtiAgentDescriptor descriptor = new AtiAgentDescriptor(
            "example.com", "v1", null, null);
        PreVerificationResult preResult = new PreVerificationResult(
            descriptor, VerificationPolicy.SILVER, expectations, null);

        when(daneVerifier.postVerify(serverCert, expectations))
            .thenReturn(VerificationResult.failure(
                VerificationResult.Type.DANE,
                VerificationResult.Status.MISMATCH,
                "TLSA fingerprint mismatch"));

        List<VerificationResult> results =
            verifier.postVerify(serverCert, preResult);

        assertThat(results).hasSize(1);
        assertThat(results.get(0).isSuccess()).isFalse();
        assertThat(results.get(0).getStatus())
            .isEqualTo(VerificationResult.Status.MISMATCH);
    }

    @Test
    void postVerifyShouldReturnUnmodifiableList() {
        AtiAgentDescriptor descriptor = new AtiAgentDescriptor(
            "example.com", "v1", null, null);
        PreVerificationResult preResult = new PreVerificationResult(
            descriptor, VerificationPolicy.BRONZE,
            Collections.emptyList(), null);

        List<VerificationResult> results =
            verifier.postVerify(serverCert, preResult);

        assertThatThrownBy(() -> results.add(
            VerificationResult.success(VerificationResult.Type.BADGE)))
            .isInstanceOf(UnsupportedOperationException.class);
    }
}
