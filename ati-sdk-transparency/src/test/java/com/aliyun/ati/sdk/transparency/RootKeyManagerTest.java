package com.aliyun.ati.sdk.transparency;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.time.Duration;
import java.util.Base64;

import com.aliyun.ati.sdk.exception.AtiException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class RootKeyManagerTest {

    private AtiTransparencyClient transparencyClient;
    private RootKeyManager rootKeyManager;

    @BeforeEach
    void setUp() {
        transparencyClient = mock(AtiTransparencyClient.class);
        rootKeyManager = new RootKeyManager(transparencyClient, Duration.ofMinutes(5));
    }

    @Test
    void shouldParseAndCacheRootKey() throws Exception {
        KeyPair keyPair = generateEcKeyPair();
        String pem = toPem(keyPair.getPublic());
        String json = "[{\"keyId\": \"key-001\", \"publicKey\": \"" + pem + "\"}]";
        when(transparencyClient.getRootKeys()).thenReturn(json);

        PublicKey key = rootKeyManager.getPublicKey("key-001");

        assertThat(key).isNotNull();
        assertThat(key.getAlgorithm()).isEqualTo("EC");
        assertThat(key.getEncoded()).isEqualTo(keyPair.getPublic().getEncoded());
    }

    @Test
    void shouldReturnCachedKeyOnSecondCall() throws Exception {
        KeyPair keyPair = generateEcKeyPair();
        String pem = toPem(keyPair.getPublic());
        String json = "[{\"keyId\": \"key-001\", \"publicKey\": \"" + pem + "\"}]";
        when(transparencyClient.getRootKeys()).thenReturn(json);

        rootKeyManager.getPublicKey("key-001");
        rootKeyManager.getPublicKey("key-001");

        verify(transparencyClient, times(1)).getRootKeys();
    }

    @Test
    void shouldThrowForUnknownKeyId() throws Exception {
        KeyPair keyPair = generateEcKeyPair();
        String pem = toPem(keyPair.getPublic());
        String json = "[{\"keyId\": \"key-001\", \"publicKey\": \"" + pem + "\"}]";
        when(transparencyClient.getRootKeys()).thenReturn(json);

        assertThatThrownBy(() -> rootKeyManager.getPublicKey("unknown-key"))
            .isInstanceOf(AtiException.class)
            .hasMessageContaining("No root key found");
    }

    @Test
    void shouldThrowForNullKeyId() {
        assertThatThrownBy(() -> rootKeyManager.getPublicKey(null))
            .isInstanceOf(NullPointerException.class);
    }

    @Test
    void shouldThrowForNullClient() {
        assertThatThrownBy(() -> new RootKeyManager(null))
            .isInstanceOf(NullPointerException.class);
    }

    @Test
    void shouldParseMultipleKeys() throws Exception {
        KeyPair keyPair1 = generateEcKeyPair();
        KeyPair keyPair2 = generateEcKeyPair();
        String pem1 = toPem(keyPair1.getPublic());
        String pem2 = toPem(keyPair2.getPublic());
        String json = "["
            + "{\"keyId\": \"key-001\", \"publicKey\": \"" + pem1 + "\"},"
            + "{\"keyId\": \"key-002\", \"publicKey\": \"" + pem2 + "\"}"
            + "]";
        when(transparencyClient.getRootKeys()).thenReturn(json);

        PublicKey key1 = rootKeyManager.getPublicKey("key-001");
        PublicKey key2 = rootKeyManager.getPublicKey("key-002");

        assertThat(key1.getEncoded()).isEqualTo(keyPair1.getPublic().getEncoded());
        assertThat(key2.getEncoded()).isEqualTo(keyPair2.getPublic().getEncoded());
    }

    @Test
    void shouldThrowOnInvalidJson() {
        when(transparencyClient.getRootKeys()).thenReturn("not-json");

        assertThatThrownBy(() -> rootKeyManager.getPublicKey("key-001"))
            .isInstanceOf(AtiException.class)
            .hasMessageContaining("Failed to parse root keys");
    }

    private static KeyPair generateEcKeyPair() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(new ECGenParameterSpec("secp256r1"));
        return gen.generateKeyPair();
    }

    private static String toPem(PublicKey key) {
        String base64 = Base64.getEncoder().encodeToString(key.getEncoded());
        return "-----BEGIN PUBLIC KEY-----\\n" + base64 + "\\n-----END PUBLIC KEY-----";
    }
}
