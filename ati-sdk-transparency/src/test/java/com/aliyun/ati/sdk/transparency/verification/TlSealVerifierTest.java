package com.aliyun.ati.sdk.transparency.verification;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import com.aliyun.ati.sdk.transparency.model.TransparencyLogResponse;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.fasterxml.jackson.databind.json.JsonMapper;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class TlSealVerifierTest {

    private TlSealVerifier verifier;
    private KeyPair keyPair;

    @BeforeEach
    void setUp() throws Exception {
        verifier = new TlSealVerifier();
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(new ECGenParameterSpec("secp256r1"));
        keyPair = gen.generateKeyPair();
    }

    @Test
    void shouldVerifyValidSeal() throws Exception {
        String json = buildSignedResponse("ACTIVE");
        ObjectMapper mapper = new ObjectMapper();
        TransparencyLogResponse response = mapper.readValue(json, TransparencyLogResponse.class);

        boolean result = verifier.verify(response, keyPair.getPublic());

        assertThat(result).isTrue();
    }

    @Test
    void shouldRejectTamperedResponse() throws Exception {
        String json = buildSignedResponse("ACTIVE");
        json = json.replace("\"ACTIVE\"", "\"REVOKED\"");
        ObjectMapper mapper = new ObjectMapper();
        TransparencyLogResponse response = mapper.readValue(json, TransparencyLogResponse.class);

        boolean result = verifier.verify(response, keyPair.getPublic());

        assertThat(result).isFalse();
    }

    @Test
    void shouldRejectWrongKey() throws Exception {
        String json = buildSignedResponse("ACTIVE");
        ObjectMapper mapper = new ObjectMapper();
        TransparencyLogResponse response = mapper.readValue(json, TransparencyLogResponse.class);

        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair wrongKey = gen.generateKeyPair();

        boolean result = verifier.verify(response, wrongKey.getPublic());

        assertThat(result).isFalse();
    }

    private String buildSignedResponse(String status) throws Exception {
        // Build the content portion matching what the verifier will construct
        Map<String, Object> content = new LinkedHashMap<>();
        content.put("status", status);
        content.put("schemaVersion", "ATI-TL-V1");

        Map<String, Object> certs = new LinkedHashMap<>();
        certs.put("serverCertFingerprint", "SHA-256:abc123");
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("agentId", "test-id");
        payload.put("certificates", certs);
        content.put("payload", payload);

        // JCS-canonicalize with same settings as the verifier
        ObjectMapper jcsMapper = JsonMapper.builder()
            .configure(MapperFeature.SORT_PROPERTIES_ALPHABETICALLY, true)
            .configure(SerializationFeature.ORDER_MAP_ENTRIES_BY_KEYS, true)
            .build();
        jcsMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
        byte[] canonicalBytes = jcsMapper.writeValueAsBytes(content);

        // Sign
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(keyPair.getPrivate());
        sig.update(canonicalBytes);
        byte[] signatureBytes = sig.sign();
        String signatureBase64 = Base64.getEncoder().encodeToString(signatureBytes);

        // Build full JSON response
        return """
            {
                "status": "%s",
                "schemaVersion": "ATI-TL-V1",
                "payload": {
                    "agentId": "test-id",
                    "certificates": {
                        "serverCertFingerprint": "SHA-256:abc123"
                    }
                },
                "seal": {
                    "canonicalization": "RFC8785-JCS",
                    "signatureAlgorithm": "SHA-256withECDSA",
                    "signatureEncoding": "DER_BASE64",
                    "keyId": "key-001",
                    "signature": "%s"
                }
            }
            """.formatted(status, signatureBase64);
    }
}
