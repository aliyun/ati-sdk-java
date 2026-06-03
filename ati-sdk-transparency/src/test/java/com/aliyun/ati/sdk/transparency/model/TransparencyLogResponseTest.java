package com.aliyun.ati.sdk.transparency.model;

import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import static org.assertj.core.api.Assertions.assertThat;

class TransparencyLogResponseTest {

    private final ObjectMapper mapper = new ObjectMapper();

    @Test
    void shouldDeserializeFullResponse() throws Exception {
        String json = """
            {
                "status": "ACTIVE",
                "schemaVersion": "ATI-TL-V1",
                "payload": {
                    "logId": "log-001",
                    "eventType": "REGISTRATION",
                    "timestamp": "2026-01-15T10:30:00Z",
                    "agentName": "my-agent",
                    "agentHost": "my-agent.example.com",
                    "version": "v1.0.0",
                    "agentId": "28b8f491-f110-4705-b8b9-dc8e91d452e0",
                    "agentStatus": "ACTIVE",
                    "certificates": {
                        "serverCertFingerprint": "SHA-256:abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890",
                        "identityCertFingerprint": "SHA-256:1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef"
                    }
                },
                "evidenceRef": {
                    "evidenceId": "ev-001",
                    "submitterId": "sub-001",
                    "evidenceType": "REGISTRATION_EVIDENCE",
                    "evidenceUri": "https://evidence.example.com/ev-001",
                    "evidenceHash": "SHA-256:fedcba"
                },
                "seal": {
                    "canonicalization": "RFC8785-JCS",
                    "digestAlgorithm": "SHA-256",
                    "signatureAlgorithm": "SHA-256withECDSA",
                    "signatureEncoding": "DER_BASE64",
                    "keyId": "key-001",
                    "signature": "MEUCIQD...",
                    "publicKey": "MFkwEwYH..."
                },
                "merkleProof": {
                    "leafHash": "abc123",
                    "leafIndex": 5,
                    "treeSize": 100,
                    "treeVersion": 1,
                    "path": ["hash1", "hash2", "hash3"],
                    "rootHash": "root123"
                }
            }
            """;

        TransparencyLogResponse response = mapper.readValue(json, TransparencyLogResponse.class);

        assertThat(response.getStatus()).isEqualTo("ACTIVE");
        assertThat(response.getSchemaVersion()).isEqualTo("ATI-TL-V1");

        TransparencyLogPayload payload = response.getPayload();
        assertThat(payload.getAgentId()).isEqualTo("28b8f491-f110-4705-b8b9-dc8e91d452e0");
        assertThat(payload.getAgentHost()).isEqualTo("my-agent.example.com");
        assertThat(payload.getCertificates().getServerCertFingerprint())
            .startsWith("SHA-256:");
        assertThat(payload.getCertificates().getIdentityCertFingerprint())
            .startsWith("SHA-256:");

        Seal seal = response.getSeal();
        assertThat(seal.getCanonicalization()).isEqualTo("RFC8785-JCS");
        assertThat(seal.getSignatureAlgorithm()).isEqualTo("SHA-256withECDSA");

        MerkleProof proof = response.getMerkleProof();
        assertThat(proof.getLeafIndex()).isEqualTo(5);
        assertThat(proof.getTreeSize()).isEqualTo(100);
        assertThat(proof.getPath()).containsExactly("hash1", "hash2", "hash3");
    }

    @Test
    void shouldIgnoreUnknownFields() throws Exception {
        String json = """
            {
                "status": "ACTIVE",
                "unknownField": "should be ignored",
                "payload": {
                    "agentId": "test-id",
                    "extraField": 42
                }
            }
            """;

        TransparencyLogResponse response = mapper.readValue(json, TransparencyLogResponse.class);

        assertThat(response.getStatus()).isEqualTo("ACTIVE");
        assertThat(response.getPayload().getAgentId()).isEqualTo("test-id");
    }
}
