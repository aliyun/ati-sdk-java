package com.aliyun.ati.sdk.transparency.verification;

import java.security.PublicKey;

import com.aliyun.ati.sdk.exception.AtiException;
import com.aliyun.ati.sdk.transparency.AtiTransparencyClient;
import com.aliyun.ati.sdk.transparency.RootKeyManager;
import com.aliyun.ati.sdk.transparency.model.TransparencyLogResponse;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class BadgeVerificationServiceTest {

    private AtiTransparencyClient transparencyClient;
    private RootKeyManager rootKeyManager;
    private TlSealVerifier sealVerifier;
    private MerkleProofVerifier merkleVerifier;
    private BadgeVerificationService service;

    @BeforeEach
    void setUp() {
        transparencyClient = mock(AtiTransparencyClient.class);
        rootKeyManager = mock(RootKeyManager.class);
        sealVerifier = mock(TlSealVerifier.class);
        merkleVerifier = mock(MerkleProofVerifier.class);
        service = new BadgeVerificationService(
            transparencyClient, rootKeyManager, sealVerifier, merkleVerifier);
    }

    @Test
    void shouldReturnVerifiedForActiveAgent() throws Exception {
        TransparencyLogResponse response = buildResponse("ACTIVE");
        PublicKey tlKey = mock(PublicKey.class);

        when(transparencyClient.getLatestLog("test-agent")).thenReturn(response);
        when(rootKeyManager.getPublicKey("key-001")).thenReturn(tlKey);
        when(sealVerifier.verify(eq(response), eq(tlKey))).thenReturn(true);
        when(merkleVerifier.verify(response.getMerkleProof())).thenReturn(true);

        ServerVerificationResult result = service.verifyServer("test-agent");

        assertThat(result.getStatus()).isEqualTo(VerificationStatus.VERIFIED);
        assertThat(result.getServerCertFingerprint()).isEqualTo("SHA-256:server123");
        assertThat(result.getAgentId()).isEqualTo("test-agent");
    }

    @Test
    void shouldReturnRevokedForNonActiveAgent() throws Exception {
        TransparencyLogResponse response = buildResponse("REVOKED");

        when(transparencyClient.getLatestLog("test-agent")).thenReturn(response);

        ServerVerificationResult result = service.verifyServer("test-agent");

        assertThat(result.getStatus()).isEqualTo(VerificationStatus.AGENT_REVOKED);
        assertThat(result.getAgentId()).isEqualTo("test-agent");
        assertThat(result.getServerCertFingerprint()).isNull();
    }

    @Test
    void shouldReturnSealInvalidWhenSealFails() throws Exception {
        TransparencyLogResponse response = buildResponse("ACTIVE");
        PublicKey tlKey = mock(PublicKey.class);

        when(transparencyClient.getLatestLog("test-agent")).thenReturn(response);
        when(rootKeyManager.getPublicKey("key-001")).thenReturn(tlKey);
        when(sealVerifier.verify(eq(response), eq(tlKey))).thenReturn(false);

        ServerVerificationResult result = service.verifyServer("test-agent");

        assertThat(result.getStatus()).isEqualTo(VerificationStatus.SEAL_INVALID);
        assertThat(result.getAgentId()).isEqualTo("test-agent");
    }

    @Test
    void shouldReturnMerkleInvalidWhenMerkleFails() throws Exception {
        TransparencyLogResponse response = buildResponse("ACTIVE");
        PublicKey tlKey = mock(PublicKey.class);

        when(transparencyClient.getLatestLog("test-agent")).thenReturn(response);
        when(rootKeyManager.getPublicKey("key-001")).thenReturn(tlKey);
        when(sealVerifier.verify(eq(response), eq(tlKey))).thenReturn(true);
        when(merkleVerifier.verify(response.getMerkleProof())).thenReturn(false);

        ServerVerificationResult result = service.verifyServer("test-agent");

        assertThat(result.getStatus()).isEqualTo(VerificationStatus.MERKLE_PROOF_INVALID);
        assertThat(result.getAgentId()).isEqualTo("test-agent");
    }

    @Test
    void shouldReturnLookupFailedOnException() {
        when(transparencyClient.getLatestLog("unknown-agent"))
            .thenThrow(new AtiException("Agent not found: unknown-agent"));

        ServerVerificationResult result = service.verifyServer("unknown-agent");

        assertThat(result.getStatus()).isEqualTo(VerificationStatus.LOOKUP_FAILED);
        assertThat(result.getAgentId()).isEqualTo("unknown-agent");
    }

    @Test
    void shouldVerifyClientWithIdentityFingerprint() throws Exception {
        TransparencyLogResponse response = buildResponse("ACTIVE");
        PublicKey tlKey = mock(PublicKey.class);

        when(transparencyClient.getLatestLog("test-agent")).thenReturn(response);
        when(rootKeyManager.getPublicKey("key-001")).thenReturn(tlKey);
        when(sealVerifier.verify(eq(response), eq(tlKey))).thenReturn(true);
        when(merkleVerifier.verify(response.getMerkleProof())).thenReturn(true);

        ClientVerificationResult result = service.verifyClient("test-agent");

        assertThat(result.getStatus()).isEqualTo(VerificationStatus.VERIFIED);
        assertThat(result.getIdentityCertFingerprint()).isEqualTo("SHA-256:identity456");
        assertThat(result.getAgentHost()).isEqualTo("agent.example.com");
        assertThat(result.getAgentId()).isEqualTo("test-agent");
    }

    private TransparencyLogResponse buildResponse(String status) throws Exception {
        String json = """
            {
                "status": "%s",
                "schemaVersion": "ATI-TL-V1",
                "payload": {
                    "agentId": "test-agent",
                    "agentHost": "agent.example.com",
                    "certificates": {
                        "serverCertFingerprint": "SHA-256:server123",
                        "identityCertFingerprint": "SHA-256:identity456"
                    }
                },
                "seal": {
                    "keyId": "key-001",
                    "signature": "sig-base64"
                },
                "merkleProof": {
                    "leafHash": "abc",
                    "leafIndex": 0,
                    "treeSize": 1,
                    "path": [],
                    "rootHash": "abc"
                }
            }
            """.formatted(status);
        return new ObjectMapper().readValue(json, TransparencyLogResponse.class);
    }
}
