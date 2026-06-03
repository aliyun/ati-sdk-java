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
        AtiDiscoveryClient discoveryClient =
            mock(AtiDiscoveryClient.class);
        DefaultConnectionVerifier connectionVerifier =
            mock(DefaultConnectionVerifier.class);

        AtiVerifiedClient client = AtiVerifiedClient.builder()
            .discoveryClient(discoveryClient)
            .connectionVerifier(connectionVerifier)
            .build();

        assertThat(client).isNotNull();
    }

    @Test
    void shouldRejectNullName() {
        AtiDiscoveryClient discoveryClient =
            mock(AtiDiscoveryClient.class);
        DefaultConnectionVerifier connectionVerifier =
            mock(DefaultConnectionVerifier.class);

        AtiVerifiedClient client = AtiVerifiedClient.builder()
            .discoveryClient(discoveryClient)
            .connectionVerifier(connectionVerifier)
            .build();

        assertThatThrownBy(() -> client.connect(null))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("name");
    }

    @Test
    void shouldRejectNullOptions() {
        AtiDiscoveryClient discoveryClient =
            mock(AtiDiscoveryClient.class);
        DefaultConnectionVerifier connectionVerifier =
            mock(DefaultConnectionVerifier.class);

        AtiVerifiedClient client = AtiVerifiedClient.builder()
            .discoveryClient(discoveryClient)
            .connectionVerifier(connectionVerifier)
            .build();

        AtiName name = AtiName.parse("ati://v1.agent.example.com");

        assertThatThrownBy(() -> client.connect(name, null))
            .isInstanceOf(NullPointerException.class)
            .hasMessageContaining("options");
    }
}
