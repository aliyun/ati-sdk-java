package com.aliyun.ati.sdk.agent;

import com.aliyun.ati.sdk.agent.verification.DefaultConnectionVerifier;
import com.aliyun.ati.sdk.discovery.AtiDiscoveryClient;
import com.aliyun.ati.sdk.discovery.AtiName;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;

class AtiVerifiedClientTest {

    @Test
    void shouldBuildWithRequiredDependencies() {
        AtiVerifiedClient client = AtiVerifiedClient.builder()
            .discoveryClient(mock(AtiDiscoveryClient.class))
            .connectionVerifier(mock(DefaultConnectionVerifier.class))
            .build();

        assertThat(client).isNotNull();
    }

    @Test
    void shouldRejectNullName() {
        AtiVerifiedClient client = AtiVerifiedClient.builder()
            .discoveryClient(mock(AtiDiscoveryClient.class))
            .connectionVerifier(mock(DefaultConnectionVerifier.class))
            .build();

        assertThatThrownBy(() -> client.connect(null))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("name");
    }

    @Test
    void shouldRejectNullOptions() {
        AtiVerifiedClient client = AtiVerifiedClient.builder()
            .discoveryClient(mock(AtiDiscoveryClient.class))
            .connectionVerifier(mock(DefaultConnectionVerifier.class))
            .build();

        AtiName name = AtiName.parse("ati://v1.agent.example.com");

        assertThatThrownBy(() -> client.connect(name, null))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("options");
    }

    @Test
    void shouldAcceptIdentityCertAndKeyPaths() {
        AtiVerifiedClient client = AtiVerifiedClient.builder()
            .discoveryClient(mock(AtiDiscoveryClient.class))
            .connectionVerifier(mock(DefaultConnectionVerifier.class))
            .identityCertificatePath("/path/to/cert.pem")
            .identityPrivateKeyPath("/path/to/key.pem")
            .build();

        assertThat(client).isNotNull();
    }

    @Test
    void shouldBuildWithoutIdentityCertPaths() {
        AtiVerifiedClient client = AtiVerifiedClient.builder()
            .discoveryClient(mock(AtiDiscoveryClient.class))
            .connectionVerifier(mock(DefaultConnectionVerifier.class))
            .build();

        assertThat(client).isNotNull();
    }
}
