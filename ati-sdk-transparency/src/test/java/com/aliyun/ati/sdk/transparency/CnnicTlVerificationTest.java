package com.aliyun.ati.sdk.transparency;

import java.util.Map;

import com.aliyun.ati.sdk.transparency.model.TransparencyLog;
import com.aliyun.ati.sdk.transparency.scitt.MerkleProofVerifier;
import com.aliyun.ati.sdk.transparency.verification.SealVerifier;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies ATI SDK can correctly validate a captured CNNIC TL response
 * including Merkle inclusion proof (RFC 9162). Historical Seal signatures
 * on this fixture use SHA-256withECDSA, which production verification rejects
 * (ADR-0009: SHA-256withRSA only).
 */
class CnnicTlVerificationTest {

    private static final String CNNIC_TL_RESPONSE = """
        {
            "status": "ACTIVE",
            "schemaVersion": "ATI-TL-V1",
            "payload": {
                "logId": "3961c1f4-9577-4347-8e8c-8670055f29d7",
                "eventType": "AGENT_REGISTERED",
                "timestamp": "2026-06-16T12:57:00.735618+08:00",
                "agentName": "ati://v1.0.4.dns-test.aliyuncs.com",
                "agentHost": "dns-test.aliyuncs.com",
                "version": "1.0.4",
                "agentId": "effae2b2-f451-4c1c-addd-212c649ef5bd",
                "agentStatus": "ACTIVE",
                "certificates": {
                    "serverCertFingerprint": "SHA-256:62faf5a64d79c99f17fdd8f8a8afa16b3e2c305b32e2c4b0cda02cdcf12335a2",
                    "identityCertFingerprint": "SHA-256:fbf23acd8e2de02efd32fbff8b88abc204cdce4b875fca2d7f428920fd4e9009"
                }
            },
            "evidenceRef": {
                "evidenceId": "aliyun-tl-effae2b2-f451-4c1c-addd-212c649ef5bd",
                "submitterId": "aliyun",
                "evidenceType": "ALIYUN_SIGNED_SUBMISSION",
                "evidenceUri": "data:application/json;base64,eyJzdWJtaXR0ZXJJZCI6ImFsaXl1biIsImNyZWF0ZV9kYXRlIjoiMTc4MTU4NTgyMDczNyIsImhhc2giOiJTSEEtMjU2OmRlMjgwMmU3OTI2ZDgwMzIxZjA3NDFlODc0OWM1Zjk4MTIzOTViMjBiN2U0NTIyODU4ZGFhMGJiMmQzNjY1MzMiLCJzaWduYXR1cmUiOiIifQ==",
                "evidenceHash": "SHA-256:971452180d19f8b94dd7ed0f395a44e90bdd7d0797eeae3b288f919d3a7ec7c5",
                "hashAlgorithm": "SHA-256",
                "hashTarget": "EVIDENCE_BYTES",
                "contentType": "application/json",
                "evidenceSchemaVersion": "ATI-EVIDENCE-V1",
                "signatureRequired": false
            },
            "seal": {
                "canonicalization": "RFC8785-JCS",
                "digestAlgorithm": "SHA-256",
                "signatureAlgorithm": "SHA-256withECDSA",
                "signatureEncoding": "DER_BASE64",
                "keyId": "ati-tl-ecdsa-v1",
                "signature": "MEQCIAIG4II0Pjzlunymh34sVuAkexAVvzO9CzVCxQ4End6GAiBJS4BuY/a+cpQdyEQ2cvQsBUm7D5Lq+CW4Tg7gbElkWA==",
                "publicKey": "-----BEGIN PUBLIC KEY-----\\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEUGIkxAhysdjZNKuS4YBcFCwRuBw3\\nAs/L+FEu/68FmD03OubC1lJ9P8rRaPPYQr8x+/5MykzS5sl6cKHad/tAKA==\\n-----END PUBLIC KEY-----"
            },
            "merkleProof": {
                "leafHash": "588dfcf15f7417ea437d7c8ba07d3e5404b5969f997bda762a9afb812a0591d6",
                "leafIndex": 4,
                "treeSize": 64,
                "treeVersion": 1,
                "path": [
                    "bbc4a05237f0ba95f1ff2934b80667597281218e2e6066f8446ad79ab6600672",
                    "6511e3fc839718c8293d5722899cb0b66bab4b8f8fcf1be86e73a00b856a2957",
                    "f0315f052906eb168e4ffa3c7216180dd1c25a917a7dd31dff0b4512a6e77c6e",
                    "88a29e65a9928b268ecf9a08c6276d50ea2c7fdfdb51dc2654f4ce3a93275e37",
                    "182429ef3393d0c1fae091c2b0a6158f47adcbf7b55b5b18a374147cede05fb6",
                    "db249a4f572478a1883d7882fb22a654f00530a7395cd33a558144bef5aff5a8"
                ],
                "rootHash": "e4bb4fd33b138600771289fdbf748f5e542bc5bd42171964fab5b96c16cd4ec6"
            }
        }
        """;

    @Test
    void shouldRejectEcdsaSealSignatureFromCnnicTl() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

        TransparencyLog log = mapper.readValue(CNNIC_TL_RESPONSE, TransparencyLog.class);
        SealVerifier.VerificationResult result = SealVerifier.verify(log);

        assertThat(result.isValid()).isFalse();
        assertThat(result.failureReason()).contains("SHA-256withRSA");
    }

    @Test
    @SuppressWarnings("unchecked")
    void shouldVerifyMerkleProofFromCnnicTl() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

        Map<String, Object> response = mapper.readValue(CNNIC_TL_RESPONSE, Map.class);
        Map<String, Object> merkleMap = (Map<String, Object>) response.get("merkleProof");

        byte[] leafHash = hexToBytes((String) merkleMap.get("leafHash"));
        long leafIndex = ((Number) merkleMap.get("leafIndex")).longValue();
        long treeSize = ((Number) merkleMap.get("treeSize")).longValue();
        byte[] rootHash = hexToBytes((String) merkleMap.get("rootHash"));

        java.util.List<String> pathHex = (java.util.List<String>) merkleMap.get("path");
        java.util.List<byte[]> path = pathHex.stream()
            .map(CnnicTlVerificationTest::hexToBytes)
            .toList();

        assertThat(MerkleProofVerifier.verifyInclusionWithHash(
                leafHash, leafIndex, treeSize, path, rootHash))
            .as("CNNIC TL Merkle inclusion proof (RFC 9162)")
            .isTrue();
    }

    @Test
    @SuppressWarnings("unchecked")
    void shouldExtractCertificateFingerprints() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

        Map<String, Object> response = mapper.readValue(CNNIC_TL_RESPONSE, Map.class);
        Map<String, Object> payload = (Map<String, Object>) response.get("payload");
        Map<String, Object> certs = (Map<String, Object>) payload.get("certificates");

        assertThat(response.get("status")).isEqualTo("ACTIVE");
        assertThat(payload.get("agentId")).isEqualTo("effae2b2-f451-4c1c-addd-212c649ef5bd");
        assertThat(payload.get("agentName")).isEqualTo("ati://v1.0.4.dns-test.aliyuncs.com");
        assertThat(certs.get("serverCertFingerprint")).asString()
            .startsWith("SHA-256:");
        assertThat(certs.get("identityCertFingerprint")).asString()
            .startsWith("SHA-256:");
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }
}
