package com.aliyun.ati.sdk.agent.verification;

import java.security.cert.X509Certificate;
import java.util.List;

import com.aliyun.ati.sdk.agent.VerificationMode;
import com.aliyun.ati.sdk.agent.VerificationPolicy;
import com.aliyun.ati.sdk.discovery.AtiAgentDescriptor;
import com.aliyun.ati.sdk.exception.AtiException;

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
            descriptor, serverCert, VerificationPolicy.PKI_ONLY);

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
            descriptor, serverCert, VerificationPolicy.DANE_AND_BADGE);

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
                descriptor, serverCert, VerificationPolicy.DANE_REQUIRED))
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
            descriptor, serverCert, VerificationPolicy.DANE_AND_BADGE);

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
            descriptor, serverCert, VerificationPolicy.DANE_REQUIRED);

        assertThatThrownBy(() -> results.add(
                VerificationResult.success(VerificationResult.Type.BADGE)))
            .isInstanceOf(UnsupportedOperationException.class);
    }

    @Test
    void shouldRejectNullDescriptor() {
        assertThatThrownBy(() -> verifier.verify(
                null, serverCert, VerificationPolicy.PKI_ONLY))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("descriptor");
    }

    @Test
    void shouldRejectNullServerCert() {
        AtiAgentDescriptor descriptor = new AtiAgentDescriptor(
            "example.com", "v1", null, null);

        assertThatThrownBy(() -> verifier.verify(
                descriptor, null, VerificationPolicy.PKI_ONLY))
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

    @Test
    void shouldRunIdcaVerificationWhenRequired() {
        IdcaChainVerifier idcaVerifier = mock(IdcaChainVerifier.class);
        DefaultConnectionVerifier v = new DefaultConnectionVerifier(
            daneVerifier, badgeVerifier, idcaVerifier);

        when(idcaVerifier.verify(serverCert))
            .thenReturn(VerificationResult.success(VerificationResult.Type.IDCA));

        AtiAgentDescriptor descriptor = new AtiAgentDescriptor(
            "example.com", "v1", null, null);
        List<VerificationResult> results = v.verify(
            descriptor, serverCert, VerificationPolicy.IDCA_REQUIRED);

        assertThat(results).hasSize(1);
        assertThat(results.get(0).getType()).isEqualTo(VerificationResult.Type.IDCA);
        assertThat(results.get(0).isSuccess()).isTrue();
    }

    @Test
    void shouldSkipIdcaWhenDisabled() {
        IdcaChainVerifier idcaVerifier = mock(IdcaChainVerifier.class);
        DefaultConnectionVerifier v = new DefaultConnectionVerifier(
            daneVerifier, badgeVerifier, idcaVerifier);

        AtiAgentDescriptor descriptor = new AtiAgentDescriptor(
            "example.com", "v1", null, null);
        List<VerificationResult> results = v.verify(
            descriptor, serverCert, VerificationPolicy.PKI_ONLY);

        assertThat(results).isEmpty();
        verify(idcaVerifier, never()).verify(any(X509Certificate.class));
    }

    @Test
    void shouldSkipIdcaWhenVerifierIsNull() {
        // Uses existing 2-arg constructor (idcaVerifier is null)
        AtiAgentDescriptor descriptor = new AtiAgentDescriptor(
            "example.com", "v1", null, null);
        VerificationPolicy policy = new VerificationPolicy("test",
            VerificationMode.DISABLED, VerificationMode.DISABLED,
            VerificationMode.REQUIRED);

        List<VerificationResult> results = verifier.verify(
            descriptor, serverCert, policy);

        assertThat(results).isEmpty();
    }

    @Test
    void shouldLogWarningOnAdvisoryIdcaFailure() {
        IdcaChainVerifier idcaVerifier = mock(IdcaChainVerifier.class);
        DefaultConnectionVerifier v = new DefaultConnectionVerifier(
            daneVerifier, badgeVerifier, idcaVerifier);

        VerificationPolicy advisory = new VerificationPolicy("IDCA_ADVISORY",
            VerificationMode.DISABLED, VerificationMode.DISABLED,
            VerificationMode.ADVISORY);

        when(idcaVerifier.verify(serverCert))
            .thenReturn(VerificationResult.failure(VerificationResult.Type.IDCA,
                VerificationResult.Status.ERROR, "cert expired"));

        AtiAgentDescriptor descriptor = new AtiAgentDescriptor(
            "example.com", "v1", null, null);
        List<VerificationResult> results = v.verify(
            descriptor, serverCert, advisory);

        assertThat(results).hasSize(1);
        assertThat(results.get(0).isSuccess()).isFalse();
        // No exception thrown -- advisory mode should only warn
    }

    @Test
    void shouldThrowOnRequiredIdcaFailure() {
        IdcaChainVerifier idcaVerifier = mock(IdcaChainVerifier.class);
        DefaultConnectionVerifier v = new DefaultConnectionVerifier(
            daneVerifier, badgeVerifier, idcaVerifier);

        when(idcaVerifier.verify(serverCert))
            .thenReturn(VerificationResult.failure(VerificationResult.Type.IDCA,
                VerificationResult.Status.MISMATCH, "chain validation failed"));

        AtiAgentDescriptor descriptor = new AtiAgentDescriptor(
            "example.com", "v1", null, null);
        assertThatThrownBy(() -> v.verify(
                descriptor, serverCert, VerificationPolicy.IDCA_REQUIRED))
            .isInstanceOf(AtiException.class)
            .hasMessageContaining("IDCA verification failed");
    }
}
