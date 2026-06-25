package com.aliyun.ati.sdk.transparency;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import com.aliyun.ati.sdk.transparency.scitt.MerkleProofVerifier;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.erdtman.jcs.JsonCanonicalizer;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Verifies badge for ats-server.asia (agentId: d4bdc2a2-17cf-4010-b7fb-58d3216572e7)
 * using real CNNIC TL response.
 */
class AtsServerBadgeTest {

    private static final String TL_RESPONSE = """
        {"status":"ACTIVE","schemaVersion":"ATI-TL-V1","payload":{"logId":"91517e87-379c-432d-af00-47eef6dbc449","eventType":"AGENT_REGISTERED","timestamp":"2026-06-24T20:49:57.514427+08:00","agentName":"ati://v1.0.0.ats-server.asia","agentHost":"ats-server.asia","version":"1.0.0","agentId":"d4bdc2a2-17cf-4010-b7fb-58d3216572e7","agentStatus":"ACTIVE","certificates":{"serverCertFingerprint":"SHA-256:213879842f4216be15291a7dc0102d10379f7d94b1f39d16a240c3b6c72a34d0","identityCertFingerprint":"SHA-256:d3bf7852b545aa8665edcb0ce75c1178363d2348aa2cff347d69f95d6c674dc9"}},"evidenceRef":{"evidenceId":"aliyun-tl-d4bdc2a2-17cf-4010-b7fb-58d3216572e7","submitterId":"aliyun","evidenceType":"ALIYUN_SIGNED_SUBMISSION","evidenceUri":"data:application/json;base64,eyJzdWJtaXR0ZXJJZCI6ImFsaXl1biIsImNyZWF0ZV9kYXRlIjoiMTc4MjMwNTM5NzUxNSIsImhhc2giOiJTSEEtMjU2OjkyNDgyOWYxYjk3ZTA1ODczOGI4NzUyYzQ3YWM4M2NiZGE2N2EwMmU2YmZiMDg0OTkyNDcyZjU3MjVhZmJmYTciLCJzaWduYXR1cmUiOiIifQ==","evidenceHash":"SHA-256:056d99182b098e6d4dce7dcedf89911c02453f10de80dd1b40f2272adbe71a8b","hashAlgorithm":"SHA-256","hashTarget":"EVIDENCE_BYTES","contentType":"application/json","evidenceSchemaVersion":"ATI-EVIDENCE-V1","signatureRequired":false},"seal":{"canonicalization":"RFC8785-JCS","digestAlgorithm":"SHA-256","signatureAlgorithm":"SHA-256withECDSA","signatureEncoding":"DER_BASE64","keyId":"ati-tl-ecdsa-v1","signature":"MEYCIQCiPmle+OrUO8hVblJTmjAHspvmxtZXcHPbjB+Oghv9IwIhAJCg0UaZS7T18JufK/YJKCL543ofMv7x21LggFfqSJtg","publicKey":"-----BEGIN PUBLIC KEY-----\\nMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEUGIkxAhysdjZNKuS4YBcFCwRuBw3\\nAs/L+FEu/68FmD03OubC1lJ9P8rRaPPYQr8x+/5MykzS5sl6cKHad/tAKA==\\n-----END PUBLIC KEY-----"},"merkleProof":{"leafHash":"f637fc6d3fa7a3ac86af4d045e86a261eecb10132dcc3328b50faaab9e795c20","leafIndex":90,"treeSize":94,"treeVersion":1,"path":["65603f93331ac764217a29213854f26a8fe00bd42211dd58214e7ffdda1e8a9a","1fe83b7298a21350005cf3310d1f20ead651a9bef4e2669f172c03e4aaecdb5b","94e1c92d4f064c5805b5635f2fe19ac8a0c5c07546ae31998f6516fa5e09ecc7","1bf3309e493b8ada030d21158fabb833c27466d223d687c92a76d0ac754c9db7","295f747acdd5b3013f8b86ff312014e34cc789b6fe7c787d6e1f43b499132eab","e4bb4fd33b138600771289fdbf748f5e542bc5bd42171964fab5b96c16cd4ec6"],"rootHash":"70763d9d891cd01b426fadc5bc962da8e2d072ad250442315b188d120bf720b6"}}
        """;

    @Test
    @SuppressWarnings("unchecked")
    void shouldVerifySealSignature() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        mapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);

        Map<String, Object> response = mapper.readValue(TL_RESPONSE, Map.class);
        Map<String, Object> seal = (Map<String, Object>) response.get("seal");

        // Parse public key
        String pem = ((String) seal.get("publicKey")).replace("\\n", "\n");
        String base64Key = pem.replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "").replaceAll("\\s+", "");
        PublicKey publicKey = KeyFactory.getInstance("EC")
            .generatePublic(new X509EncodedKeySpec(Base64.getDecoder().decode(base64Key)));

        // Build canonical content
        Map<String, Object> content = new LinkedHashMap<>();
        content.put("status", response.get("status"));
        content.put("schemaVersion", response.get("schemaVersion"));
        content.put("payload", response.get("payload"));
        content.put("evidenceRef", response.get("evidenceRef"));

        String contentJson = mapper.writeValueAsString(content);
        JsonCanonicalizer canonicalizer = new JsonCanonicalizer(contentJson);
        byte[] canonicalBytes = canonicalizer.getEncodedUTF8();

        // Verify signature
        byte[] signatureBytes = Base64.getDecoder().decode((String) seal.get("signature"));
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initVerify(publicKey);
        sig.update(canonicalBytes);

        assertThat(sig.verify(signatureBytes))
            .as("ats-server.asia seal signature verification")
            .isTrue();
    }

    @Test
    @SuppressWarnings("unchecked")
    void shouldVerifyMerkleProof() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

        Map<String, Object> response = mapper.readValue(TL_RESPONSE, Map.class);
        Map<String, Object> merkle = (Map<String, Object>) response.get("merkleProof");

        byte[] leafHash = hexToBytes((String) merkle.get("leafHash"));
        long leafIndex = ((Number) merkle.get("leafIndex")).longValue();
        long treeSize = ((Number) merkle.get("treeSize")).longValue();
        byte[] rootHash = hexToBytes((String) merkle.get("rootHash"));

        java.util.List<String> pathHex = (java.util.List<String>) merkle.get("path");
        java.util.List<byte[]> path = pathHex.stream()
            .map(AtsServerBadgeTest::hexToBytes).toList();

        assertThat(MerkleProofVerifier.verifyInclusionWithHash(
                leafHash, leafIndex, treeSize, path, rootHash))
            .as("ats-server.asia merkle inclusion proof")
            .isTrue();
    }

    @Test
    @SuppressWarnings("unchecked")
    void shouldExtractCorrectFingerprints() throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

        Map<String, Object> response = mapper.readValue(TL_RESPONSE, Map.class);
        Map<String, Object> payload = (Map<String, Object>) response.get("payload");
        Map<String, Object> certs = (Map<String, Object>) payload.get("certificates");

        assertThat(response.get("status")).isEqualTo("ACTIVE");
        assertThat(payload.get("agentId")).isEqualTo("d4bdc2a2-17cf-4010-b7fb-58d3216572e7");
        assertThat(payload.get("agentName")).isEqualTo("ati://v1.0.0.ats-server.asia");
        assertThat(payload.get("agentHost")).isEqualTo("ats-server.asia");
        assertThat(certs.get("serverCertFingerprint"))
            .isEqualTo("SHA-256:213879842f4216be15291a7dc0102d10379f7d94b1f39d16a240c3b6c72a34d0");
        assertThat(certs.get("identityCertFingerprint"))
            .isEqualTo("SHA-256:d3bf7852b545aa8665edcb0ce75c1178363d2348aa2cff347d69f95d6c674dc9");
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
