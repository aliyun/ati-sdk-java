package com.aliyun.ati.sdk.transparency.verification;

import com.aliyun.ati.sdk.transparency.model.TransparencyLog;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.erdtman.jcs.JsonCanonicalizer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class SealVerifierTest {

    private static final ObjectMapper MAPPER = new ObjectMapper()
        .setSerializationInclusion(JsonInclude.Include.NON_NULL);

    /**
     * Production-shaped TL body (seal replaced with a locally signed value).
     * evidenceRef includes signature metadata that EvidenceRef does not model.
     */
    private static final String TL_BODY = """
        {
          "status": "ACTIVE",
          "schemaVersion": "ATI-TL-V1",
          "payload": {
            "logId": "28b8f491-f110-4705-b8b9-dc8e91d452e0",
            "eventType": "AGENT_REGISTERED",
            "timestamp": "2026-05-18T16:00:00+08:00",
            "agentName": "ati://v1.demo.example.com",
            "agentDisplayName": "demo-agent",
            "agentHost": "demo.example.com",
            "version": "1.0.0",
            "agentId": "agent-001",
            "agentStatus": "ACTIVE",
            "certificates": {
              "serverCertFingerprint": "SHA-256:server-cert-fingerprint",
              "identityCertFingerprint": "SHA-256:identity-cert-fingerprint"
            }
          },
          "evidenceRef": {
            "evidenceId": "aliyun-evidence-agent-001",
            "submitterId": "aliyun",
            "evidenceType": "ALIYUN_SIGNED_SUBMISSION",
            "evidenceUri": "https://example.aliyun.com/ati/evidence/agent-001.json",
            "evidenceHash": "SHA-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "hashAlgorithm": "SHA-256",
            "hashTarget": "EVIDENCE_BYTES",
            "contentType": "application/json",
            "evidenceSchemaVersion": "ATI-EVIDENCE-V1",
            "signatureRequired": true,
            "signatureAlgorithm": "SHA-256withECDSA",
            "signatureEncoding": "DER_BASE64",
            "signatureCanonicalization": "RFC8785-JCS",
            "signedContentLocation": "signedContent",
            "signatureLocation": "signature",
            "keyId": "aliyun-ati-v1"
          }
        }
        """;

    @Test
    @DisplayName("Seal verify should succeed for production evidenceRef extra keys after TransparencyLog parse")
    void shouldVerifySealForProductionTlEvidenceRefShape() throws Exception {
        KeyPair keyPair = generateEcKeyPair();

        @SuppressWarnings("unchecked")
        Map<String, Object> response = MAPPER.readValue(TL_BODY, Map.class);

        Map<String, Object> signedContent = new LinkedHashMap<>();
        signedContent.put("status", response.get("status"));
        signedContent.put("schemaVersion", response.get("schemaVersion"));
        signedContent.put("payload", response.get("payload"));
        signedContent.put("evidenceRef", response.get("evidenceRef"));

        byte[] canonicalBytes = new JsonCanonicalizer(MAPPER.writeValueAsString(signedContent))
            .getEncodedUTF8();

        Map<String, Object> seal = new LinkedHashMap<>();
        seal.put("canonicalization", "RFC8785-JCS");
        seal.put("digestAlgorithm", "SHA-256");
        seal.put("signatureAlgorithm", "SHA-256withECDSA");
        seal.put("signatureEncoding", "DER_BASE64");
        seal.put("keyId", "ati-tl-ecdsa-v1");
        seal.put("signature", sign(keyPair, canonicalBytes));
        seal.put("publicKey", toPem(keyPair));
        response.put("seal", seal);

        TransparencyLog log = MAPPER.readValue(MAPPER.writeValueAsString(response), TransparencyLog.class);

        SealVerifier.VerificationResult result = SealVerifier.verify(log);

        assertThat(result.isValid()).isTrue();
        assertThat(result.sealValid()).isTrue();
        assertThat(log.getPayload()).containsEntry("agentDisplayName", "demo-agent");
        assertThat(log.getEvidenceRef().getEvidenceId()).isEqualTo("aliyun-evidence-agent-001");
        assertThat(log.getRawEvidenceRef()).containsKeys(
            "signatureAlgorithm",
            "signatureEncoding",
            "signatureCanonicalization",
            "signedContentLocation",
            "signatureLocation",
            "keyId");
    }

    private static KeyPair generateEcKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        return generator.generateKeyPair();
    }

    private static String sign(KeyPair keyPair, byte[] canonicalBytes) throws Exception {
        Signature signer = Signature.getInstance("SHA256withECDSA");
        signer.initSign(keyPair.getPrivate());
        signer.update(canonicalBytes);
        return Base64.getEncoder().encodeToString(signer.sign());
    }

    private static String toPem(KeyPair keyPair) {
        String body = Base64.getMimeEncoder(64, new byte[]{'\n'})
            .encodeToString(keyPair.getPublic().getEncoded());
        return "-----BEGIN PUBLIC KEY-----\n" + body + "\n-----END PUBLIC KEY-----";
    }
}
