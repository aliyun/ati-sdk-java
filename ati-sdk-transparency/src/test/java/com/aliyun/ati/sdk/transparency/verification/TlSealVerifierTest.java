package com.aliyun.ati.sdk.transparency.verification;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import com.aliyun.ati.sdk.transparency.model.TransparencyLogResponse;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.erdtman.jcs.JsonCanonicalizer;
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
        Map<String, Object> content = new LinkedHashMap<>();
        content.put("status", status);
        content.put("schemaVersion", "ATI-TL-V1");

        Map<String, Object> certs = new LinkedHashMap<>();
        certs.put("serverCertFingerprint", "SHA-256:abc123");
        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("agentId", "test-id");
        payload.put("certificates", certs);
        content.put("payload", payload);

        Map<String, Object> evidenceRef = new LinkedHashMap<>();
        evidenceRef.put("evidenceId", "ev-001");
        evidenceRef.put("evidenceUri", "https://example.com/evidence");
        content.put("evidenceRef", evidenceRef);

        ObjectMapper mapper = new ObjectMapper();
        String json = mapper.writeValueAsString(content);
        JsonCanonicalizer canonicalizer = new JsonCanonicalizer(json);
        byte[] canonicalBytes = canonicalizer.getEncodedUTF8();

        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(keyPair.getPrivate());
        sig.update(canonicalBytes);
        byte[] signatureBytes = sig.sign();
        String signatureBase64 = Base64.getEncoder().encodeToString(signatureBytes);

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
                "evidenceRef": {
                    "evidenceId": "ev-001",
                    "evidenceUri": "https://example.com/evidence"
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
