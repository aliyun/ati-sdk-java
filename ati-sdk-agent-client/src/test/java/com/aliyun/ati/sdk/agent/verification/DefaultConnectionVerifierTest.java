package com.aliyun.ati.sdk.agent.verification;

import java.security.cert.X509Certificate;
import java.util.Collections;
import java.util.List;

import com.aliyun.ati.sdk.agent.VerificationMode;
import com.aliyun.ati.sdk.agent.VerificationPolicy;
import com.aliyun.ati.sdk.discovery.AtiAgentDescriptor;
import com.aliyun.ati.sdk.exception.AtiException;
import com.aliyun.ati.sdk.transparency.verification.ServerVerificationResult;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
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

    @Test
    void shouldSkipDisabledVerifications() {
        AtiAgentDescriptor descriptor = new AtiAgentDescriptor(
            "example.com", "v1", null, "agent-001");

        List<VerificationResult> results = verifier.verify(
            descriptor, serverCert, VerificationPolicy.BRONZE);

        assertThat(results).isEmpty();
        verify(daneVerifier, never())
            .verify(anyString(), anyInt(), any(X509Certificate.class));
        verify(badgeVerifier, never())
            .verify(anyString(), any(X509Certificate.class));
    }

    @Test
    void shouldRunBothVerifications() {
        AtiAgentDescriptor descriptor = new AtiAgentDescriptor(
            "example.com", "v1", null, "agent-001");

        when(daneVerifier.verify("example.com", 443, serverCert))
            .thenReturn(VerificationResult.success(
                VerificationResult.Type.DANE));
        when(badgeVerifier.verify("agent-001", serverCert))
            .thenReturn(VerificationResult.success(
                VerificationResult.Type.BADGE));

        List<VerificationResult> results = verifier.verify(
            descriptor, serverCert, VerificationPolicy.GOLD);

        assertThat(results).hasSize(2);
        assertThat(results.get(0).getType())
            .isEqualTo(VerificationResult.Type.DANE);
        assertThat(results.get(0).isSuccess()).isTrue();
        assertThat(results.get(1).getType())
            .isEqualTo(VerificationResult.Type.BADGE);
        assertThat(results.get(1).isSuccess()).isTrue();
    }

    @Test
    void shouldThrowOnRequiredFailure() {
        AtiAgentDescriptor descriptor = new AtiAgentDescriptor(
            "example.com", "v1", null, "agent-001");

        when(daneVerifier.verify("example.com", 443, serverCert))
            .thenReturn(VerificationResult.failure(
                VerificationResult.Type.DANE,
                VerificationResult.Status.MISMATCH,
                "TLSA fingerprint mismatch"));

        assertThatThrownBy(() -> verifier.verify(
                descriptor, serverCert, VerificationPolicy.SILVER))
            .isInstanceOf(AtiException.class)
            .hasMessageContaining("DANE verification failed");
    }

    @Test
    void shouldLogWarningOnAdvisoryFailure() {
        AtiAgentDescriptor descriptor = new AtiAgentDescriptor(
            "example.com", "v1", null, "agent-001");

        VerificationPolicy advisoryPolicy = new VerificationPolicy(
            "DANE_ADVISORY",
            VerificationMode.ADVISORY,
            VerificationMode.DISABLED);

        when(daneVerifier.verify("example.com", 443, serverCert))
            .thenReturn(VerificationResult.failure(
                VerificationResult.Type.DANE,
                VerificationResult.Status.NOT_FOUND,
                "No TLSA record"));

        List<VerificationResult> results = verifier.verify(
            descriptor, serverCert, advisoryPolicy);

        assertThat(results).hasSize(1);
        assertThat(results.get(0).isSuccess()).isFalse();
        assertThat(results.get(0).getStatus())
            .isEqualTo(VerificationResult.Status.NOT_FOUND);
    }

    @Test
    void shouldSkipBadgeWhenAgentIdIsNull() {
        AtiAgentDescriptor descriptor = new AtiAgentDescriptor(
            "example.com", "v1", null, null);

        when(daneVerifier.verify("example.com", 443, serverCert))
            .thenReturn(VerificationResult.success(
                VerificationResult.Type.DANE));

        List<VerificationResult> results = verifier.verify(
            descriptor, serverCert, VerificationPolicy.GOLD);

        assertThat(results).hasSize(1);
        assertThat(results.get(0).getType())
            .isEqualTo(VerificationResult.Type.DANE);
        verify(badgeVerifier, never())
            .verify(anyString(), any(X509Certificate.class));
    }

    @Test
    void shouldReturnUnmodifiableList() {
        AtiAgentDescriptor descriptor = new AtiAgentDescriptor(
            "example.com", "v1", null, "agent-001");

        when(daneVerifier.verify("example.com", 443, serverCert))
            .thenReturn(VerificationResult.success(
                VerificationResult.Type.DANE));

        List<VerificationResult> results = verifier.verify(
            descriptor, serverCert, VerificationPolicy.SILVER);

        assertThatThrownBy(() -> results.add(
                VerificationResult.success(VerificationResult.Type.BADGE)))
            .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void shouldRejectNullDescriptor() {
        assertThatThrownBy(() -> verifier.verify(
                null, serverCert, VerificationPolicy.BRONZE))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("descriptor");
    }

    @Test
    void shouldRejectNullServerCert() {
        AtiAgentDescriptor descriptor = new AtiAgentDescriptor(
            "example.com", "v1", null, null);

        assertThatThrownBy(() -> verifier.verify(
                descriptor, null, VerificationPolicy.BRONZE))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("serverCert");
    }

    @Test
    void shouldRejectNullPolicy() {
        AtiAgentDescriptor descriptor = new AtiAgentDescriptor(
            "example.com", "v1", null, null);

        assertThatThrownBy(() -> verifier.verify(
                descriptor, serverCert, null))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("policy");
    }

    // --- preVerify tests ---

    @Test
    void shouldSkipDisabledPreVerifications() {
        AtiAgentDescriptor descriptor = new AtiAgentDescriptor(
            "example.com", "v1", null, "agent-001");

        PreVerificationResult result =
            verifier.preVerify(descriptor, VerificationPolicy.BRONZE);

        assertThat(result.getDaneExpectations()).isEmpty();
        assertThat(result.getBadgeResult()).isNull();
        verify(daneVerifier, never())
            .getTlsaExpectations(anyString(), anyInt());
        verify(badgeVerifier, never()).preVerify(anyString());
    }

    @Test
    void shouldQueryDaneAndBadgeOnPreVerify() {
        AtiAgentDescriptor descriptor = new AtiAgentDescriptor(
            "example.com", "v1", null, "agent-001");

        List<DaneTlsaVerifier.TlsaExpectation> expectations =
            List.of(new DaneTlsaVerifier.TlsaExpectation(
                1, 1, new byte[32]));
        when(daneVerifier.getTlsaExpectations("example.com", 443))
            .thenReturn(expectations);

        ServerVerificationResult badgeResult =
            ServerVerificationResult.verified("SHA-256:abc", "agent-001");
        when(badgeVerifier.preVerify("agent-001"))
            .thenReturn(badgeResult);

        PreVerificationResult result =
            verifier.preVerify(descriptor, VerificationPolicy.GOLD);

        assertThat(result.getDaneExpectations()).hasSize(1);
        assertThat(result.getBadgeResult()).isSameAs(badgeResult);
        assertThat(result.getDescriptor()).isSameAs(descriptor);
        assertThat(result.getPolicy())
            .isEqualTo(VerificationPolicy.GOLD);
    }

    @Test
    void shouldSkipBadgePreVerifyWhenAgentIdNull() {
        AtiAgentDescriptor descriptor = new AtiAgentDescriptor(
            "example.com", "v1", null, null);

        when(daneVerifier.getTlsaExpectations("example.com", 443))
            .thenReturn(Collections.emptyList());

        PreVerificationResult result =
            verifier.preVerify(descriptor, VerificationPolicy.GOLD);

        assertThat(result.getBadgeResult()).isNull();
        verify(badgeVerifier, never()).preVerify(anyString());
    }

    @Test
    void shouldHandleDaneExceptionOnPreVerify() {
        AtiAgentDescriptor descriptor = new AtiAgentDescriptor(
            "example.com", "v1", null, null);

        when(daneVerifier.getTlsaExpectations("example.com", 443))
            .thenThrow(new RuntimeException("DNS failure"));

        PreVerificationResult result =
            verifier.preVerify(descriptor, VerificationPolicy.SILVER);

        assertThat(result.getDaneExpectations()).isEmpty();
    }

    @Test
    void shouldHandleBadgeExceptionOnPreVerify() {
        AtiAgentDescriptor descriptor = new AtiAgentDescriptor(
            "example.com", "v1", null, "agent-001");

        when(daneVerifier.getTlsaExpectations("example.com", 443))
            .thenReturn(Collections.emptyList());
        when(badgeVerifier.preVerify("agent-001"))
            .thenThrow(new RuntimeException("TL failure"));

        PreVerificationResult result =
            verifier.preVerify(descriptor, VerificationPolicy.GOLD);

        assertThat(result.getBadgeResult()).isNull();
    }

    @Test
    void shouldRejectNullDescriptorOnPreVerify() {
        assertThatThrownBy(
                () -> verifier.preVerify(null, VerificationPolicy.BRONZE))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("descriptor");
    }

    @Test
    void shouldRejectNullPolicyOnPreVerify() {
        AtiAgentDescriptor descriptor = new AtiAgentDescriptor(
            "example.com", "v1", null, null);

        assertThatThrownBy(
                () -> verifier.preVerify(descriptor, null))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("policy");
    }

    // --- postVerify tests ---

    @Test
    void shouldRunDaneAndBadgeOnPostVerify() {
        List<DaneTlsaVerifier.TlsaExpectation> expectations =
            List.of(new DaneTlsaVerifier.TlsaExpectation(
                1, 1, new byte[32]));
        ServerVerificationResult badgeResult =
            ServerVerificationResult.verified(
                "SHA-256:abc", "agent-001");

        AtiAgentDescriptor descriptor = new AtiAgentDescriptor(
            "example.com", "v1", null, "agent-001");
        PreVerificationResult preResult = new PreVerificationResult(
            descriptor, VerificationPolicy.GOLD,
            expectations, badgeResult);

        when(daneVerifier.postVerify(serverCert, expectations))
            .thenReturn(VerificationResult.success(
                VerificationResult.Type.DANE));
        when(badgeVerifier.postVerify(serverCert, badgeResult))
            .thenReturn(VerificationResult.success(
                VerificationResult.Type.BADGE));

        List<VerificationResult> results =
            verifier.postVerify(serverCert, preResult);

        assertThat(results).hasSize(2);
        assertThat(results.get(0).getType())
            .isEqualTo(VerificationResult.Type.DANE);
        assertThat(results.get(1).getType())
            .isEqualTo(VerificationResult.Type.BADGE);
    }

    @Test
    void shouldSkipDisabledPostVerifications() {
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
    void shouldThrowOnRequiredPostVerifyFailure() {
        List<DaneTlsaVerifier.TlsaExpectation> expectations =
            List.of(new DaneTlsaVerifier.TlsaExpectation(
                1, 1, new byte[32]));
        AtiAgentDescriptor descriptor = new AtiAgentDescriptor(
            "example.com", "v1", null, null);
        PreVerificationResult preResult = new PreVerificationResult(
            descriptor, VerificationPolicy.SILVER,
            expectations, null);

        when(daneVerifier.postVerify(serverCert, expectations))
            .thenReturn(VerificationResult.failure(
                VerificationResult.Type.DANE,
                VerificationResult.Status.MISMATCH,
                "TLSA fingerprint mismatch"));

        assertThatThrownBy(
                () -> verifier.postVerify(serverCert, preResult))
            .isInstanceOf(AtiException.class)
            .hasMessageContaining("DANE verification failed");
    }

    @Test
    void shouldRejectNullCertOnPostVerify() {
        AtiAgentDescriptor descriptor = new AtiAgentDescriptor(
            "example.com", "v1", null, null);
        PreVerificationResult preResult = new PreVerificationResult(
            descriptor, VerificationPolicy.BRONZE,
            Collections.emptyList(), null);

        assertThatThrownBy(
                () -> verifier.postVerify(null, preResult))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("serverCert");
    }

    @Test
    void shouldRejectNullPreResultOnPostVerify() {
        assertThatThrownBy(
                () -> verifier.postVerify(serverCert, null))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("preResult");
    }
}
