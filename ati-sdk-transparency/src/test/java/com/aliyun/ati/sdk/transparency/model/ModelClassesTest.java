package com.aliyun.ati.sdk.transparency.model;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.time.OffsetDateTime;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Tests for model classes to ensure getters, setters, and toString work correctly.
 */
class ModelClassesTest {

    @Test
    @DisplayName("CertificateInfo getters and setters should work")
    void certificateInfoGettersAndSettersWork() {
        CertificateInfo info = new CertificateInfo();

        info.setFingerprint("SHA256:abc123");
        info.setType(CertType.X509_DV_SERVER);

        assertThat(info.getFingerprint()).isEqualTo("SHA256:abc123");
        assertThat(info.getType()).isEqualTo(CertType.X509_DV_SERVER);
    }

    @Test
    @DisplayName("CertificateInfo constructor should work")
    void certificateInfoConstructorWorks() {
        CertificateInfo info = new CertificateInfo("fp123", CertType.X509_EV_CLIENT);

        assertThat(info.getFingerprint()).isEqualTo("fp123");
        assertThat(info.getType()).isEqualTo(CertType.X509_EV_CLIENT);
    }

    @Test
    @DisplayName("CertificateInfo toString should work")
    void certificateInfoToStringWorks() {
        CertificateInfo info = new CertificateInfo();
        info.setFingerprint("fp123");

        String str = info.toString();
        assertThat(str).contains("fp123");
    }

    @Test
    @DisplayName("MerkleProof getters and setters should work")
    void merkleProofGettersAndSettersWork() {
        MerkleProof proof = new MerkleProof();

        proof.setLeafIndex(100L);
        proof.setTreeSize(1000L);
        proof.setTreeVersion(5L);
        proof.setRootHash("roothash123");
        proof.setLeafHash("leafhash456");
        proof.setRootSignature("sig789");
        proof.setPath(List.of("hash1", "hash2"));

        assertThat(proof.getLeafIndex()).isEqualTo(100L);
        assertThat(proof.getTreeSize()).isEqualTo(1000L);
        assertThat(proof.getTreeVersion()).isEqualTo(5L);
        assertThat(proof.getRootHash()).isEqualTo("roothash123");
        assertThat(proof.getLeafHash()).isEqualTo("leafhash456");
        assertThat(proof.getRootSignature()).isEqualTo("sig789");
        assertThat(proof.getPath()).containsExactly("hash1", "hash2");
    }

    @Test
    @DisplayName("MerkleProof toString should work")
    void merkleProofToStringWorks() {
        MerkleProof proof = new MerkleProof();
        proof.setLeafHash("leafhash");
        proof.setRootHash("roothash");

        String str = proof.toString();
        assertThat(str).contains("leafhash");
        assertThat(str).contains("roothash");
    }

    @Test
    @DisplayName("PaginationInfo getters and setters should work")
    void paginationInfoGettersAndSettersWork() {
        PaginationInfo info = new PaginationInfo();

        info.setFirst("/api?page=1");
        info.setPrevious("/api?page=2");
        info.setNext("/api?page=4");
        info.setLast("/api?page=10");
        info.setTotal(500L);
        info.setNextOffset(100);

        assertThat(info.getFirst()).isEqualTo("/api?page=1");
        assertThat(info.getPrevious()).isEqualTo("/api?page=2");
        assertThat(info.getNext()).isEqualTo("/api?page=4");
        assertThat(info.getLast()).isEqualTo("/api?page=10");
        assertThat(info.getTotal()).isEqualTo(500L);
        assertThat(info.getNextOffset()).isEqualTo(100);
    }

    @Test
    @DisplayName("PaginationInfo toString should work")
    void paginationInfoToStringWorks() {
        PaginationInfo info = new PaginationInfo();
        info.setTotal(500L);

        String str = info.toString();
        assertThat(str).contains("500");
    }

    @Test
    @DisplayName("CheckpointSignature getters and setters should work")
    void checkpointSignatureGettersAndSettersWork() {
        CheckpointSignature sig = new CheckpointSignature();
        OffsetDateTime now = OffsetDateTime.now();

        sig.setSignerName("signer-1");
        sig.setSignatureType("Ed25519");
        sig.setAlgorithm("SHA256");
        sig.setKeyHash("keyhash123");
        sig.setRawSignature("rawsig");
        sig.setValid(true);
        sig.setKmsKeyId("kms-key-1");
        sig.setTimestamp(now);
        sig.setJwsSignature("jws-sig");

        Map<String, Object> header = new HashMap<>();
        header.put("alg", "ES256");
        sig.setJwsHeader(header);

        Map<String, Object> payload = new HashMap<>();
        payload.put("sub", "test");
        sig.setJwsPayload(payload);

        assertThat(sig.getSignerName()).isEqualTo("signer-1");
        assertThat(sig.getSignatureType()).isEqualTo("Ed25519");
        assertThat(sig.getAlgorithm()).isEqualTo("SHA256");
        assertThat(sig.getKeyHash()).isEqualTo("keyhash123");
        assertThat(sig.getRawSignature()).isEqualTo("rawsig");
        assertThat(sig.getValid()).isTrue();
        assertThat(sig.getKmsKeyId()).isEqualTo("kms-key-1");
        assertThat(sig.getTimestamp()).isEqualTo(now);
        assertThat(sig.getJwsSignature()).isEqualTo("jws-sig");
        assertThat(sig.getJwsHeader()).containsEntry("alg", "ES256");
        assertThat(sig.getJwsPayload()).containsEntry("sub", "test");
    }

    @Test
    @DisplayName("CheckpointSignature toString should work")
    void checkpointSignatureToStringWorks() {
        CheckpointSignature sig = new CheckpointSignature();
        sig.setSignerName("signer-1");
        sig.setAlgorithm("SHA256");

        String str = sig.toString();
        assertThat(str).contains("signer-1");
        assertThat(str).contains("SHA256");
    }

    @Test
    @DisplayName("CheckpointResponse getters and setters should work")
    void checkpointResponseGettersAndSettersWork() {
        CheckpointResponse response = new CheckpointResponse();
        CheckpointSignature sig = new CheckpointSignature();

        response.setLogSize(1000L);
        response.setTreeHeight(10);
        response.setRootHash("root123");
        response.setOriginName("origin-name");
        response.setCheckpointFormat("RFC6962");
        response.setCheckpointText("checkpoint-text");
        response.setPublicKeyPem("-----BEGIN PUBLIC KEY-----");
        response.setSignatures(List.of(sig));

        assertThat(response.getLogSize()).isEqualTo(1000L);
        assertThat(response.getTreeHeight()).isEqualTo(10);
        assertThat(response.getRootHash()).isEqualTo("root123");
        assertThat(response.getOriginName()).isEqualTo("origin-name");
        assertThat(response.getCheckpointFormat()).isEqualTo("RFC6962");
        assertThat(response.getCheckpointText()).isEqualTo("checkpoint-text");
        assertThat(response.getPublicKeyPem()).isEqualTo("-----BEGIN PUBLIC KEY-----");
        assertThat(response.getSignatures()).containsExactly(sig);
    }

    @Test
    @DisplayName("CheckpointResponse toString should work")
    void checkpointResponseToStringWorks() {
        CheckpointResponse response = new CheckpointResponse();
        response.setLogSize(1000L);
        response.setRootHash("root123");

        String str = response.toString();
        assertThat(str).contains("1000");
        assertThat(str).contains("root123");
    }

    @Test
    @DisplayName("CheckpointHistoryParams builder should work")
    void checkpointHistoryParamsBuilderWorks() {
        OffsetDateTime since = OffsetDateTime.now();
        CheckpointHistoryParams params = CheckpointHistoryParams.builder()
            .limit(25)
            .offset(50)
            .fromSize(100)
            .toSize(200)
            .since(since)
            .order("desc")
            .build();

        assertThat(params.getLimit()).isEqualTo(25);
        assertThat(params.getOffset()).isEqualTo(50);
        assertThat(params.getFromSize()).isEqualTo(100);
        assertThat(params.getToSize()).isEqualTo(200);
        assertThat(params.getSince()).isEqualTo(since);
        assertThat(params.getOrder()).isEqualTo("desc");
    }

    @Test
    @DisplayName("CheckpointHistoryParams setters should work")
    void checkpointHistoryParamsSettersWork() {
        CheckpointHistoryParams params = new CheckpointHistoryParams();
        OffsetDateTime since = OffsetDateTime.now();

        params.setLimit(10);
        params.setOffset(20);
        params.setFromSize(30);
        params.setToSize(40);
        params.setSince(since);
        params.setOrder("asc");

        assertThat(params.getLimit()).isEqualTo(10);
        assertThat(params.getOffset()).isEqualTo(20);
        assertThat(params.getFromSize()).isEqualTo(30);
        assertThat(params.getToSize()).isEqualTo(40);
        assertThat(params.getSince()).isEqualTo(since);
        assertThat(params.getOrder()).isEqualTo("asc");
    }

    @Test
    @DisplayName("TransparencyLogAudit getters and setters should work")
    void transparencyLogAuditGettersAndSettersWork() {
        TransparencyLogAudit audit = new TransparencyLogAudit();
        TransparencyLog log = new TransparencyLog();

        audit.setRecords(List.of(log));

        assertThat(audit.getRecords()).containsExactly(log);
    }

    @Test
    @DisplayName("TransparencyLogAudit toString should work")
    void transparencyLogAuditToStringWorks() {
        TransparencyLogAudit audit = new TransparencyLogAudit();
        audit.setRecords(List.of(new TransparencyLog(), new TransparencyLog()));

        String str = audit.toString();
        assertThat(str).contains("2");
    }

    @Test
    @DisplayName("TransparencyLogAudit toString with null records")
    void transparencyLogAuditToStringWithNullRecords() {
        TransparencyLogAudit audit = new TransparencyLogAudit();

        String str = audit.toString();
        assertThat(str).contains("0");
    }

    @Test
    @DisplayName("CertType enum values exist")
    void certTypeEnumValuesExist() {
        assertThat(CertType.values()).contains(
            CertType.X509_DV_SERVER,
            CertType.X509_EV_CLIENT,
            CertType.X509_EV_SERVER,
            CertType.X509_OV_CLIENT,
            CertType.X509_OV_SERVER
        );
    }

    @Test
    @DisplayName("CertType getValue should return string value")
    void certTypeGetValueWorks() {
        assertThat(CertType.X509_DV_SERVER.getValue()).isEqualTo("X509-DV-SERVER");
        assertThat(CertType.X509_EV_CLIENT.getValue()).isEqualTo("X509-EV-CLIENT");
    }

    @Test
    @DisplayName("CertType fromString should parse correctly")
    void certTypeFromStringWorks() {
        assertThat(CertType.fromString("X509-DV-SERVER")).isEqualTo(CertType.X509_DV_SERVER);
        assertThat(CertType.fromString("x509-dv-server")).isEqualTo(CertType.X509_DV_SERVER);
        assertThat(CertType.fromString(null)).isNull();
        assertThat(CertType.fromString("UNKNOWN")).isNull();
    }

    // ==================== TransparencyLogAtiV1 Tests ====================

    @Test
    @DisplayName("TransparencyLogAtiV1 getters and setters should work")
    void transparencyLogAtiV1GettersAndSettersWork() {
        TransparencyLogAtiV1 payload = new TransparencyLogAtiV1();

        payload.setLogId("log-123");
        payload.setEventType("AGENT_REGISTERED");
        payload.setTimestamp("2026-01-15T10:00:00+08:00");
        payload.setAgentName("ati://v1.0.0.agent.example.com");
        payload.setAgentHost("agent.example.com");
        payload.setVersion("1.0.0");
        payload.setAgentId("some-uuid");
        payload.setAgentStatus("ACTIVE");

        assertThat(payload.getLogId()).isEqualTo("log-123");
        assertThat(payload.getEventType()).isEqualTo("AGENT_REGISTERED");
        assertThat(payload.getTimestamp()).isEqualTo("2026-01-15T10:00:00+08:00");
        assertThat(payload.getAgentName()).isEqualTo("ati://v1.0.0.agent.example.com");
        assertThat(payload.getAgentHost()).isEqualTo("agent.example.com");
        assertThat(payload.getVersion()).isEqualTo("1.0.0");
        assertThat(payload.getAgentId()).isEqualTo("some-uuid");
        assertThat(payload.getAgentStatus()).isEqualTo("ACTIVE");
    }

    @Test
    @DisplayName("TransparencyLogAtiV1 certificates should work")
    void transparencyLogAtiV1CertificatesWork() {
        TransparencyLogAtiV1 payload = new TransparencyLogAtiV1();

        TransparencyLogAtiV1.Certificates certs = new TransparencyLogAtiV1.Certificates();
        certs.setServerCertFingerprint("SHA-256:abc123");
        certs.setIdentityCertFingerprint("SHA-256:def456");
        payload.setCertificates(certs);

        assertThat(payload.getCertificates()).isSameAs(certs);
        assertThat(payload.getCertificates().getServerCertFingerprint()).isEqualTo("SHA-256:abc123");
        assertThat(payload.getCertificates().getIdentityCertFingerprint()).isEqualTo("SHA-256:def456");
    }

    @Test
    @DisplayName("TransparencyLogAtiV1 toString should work")
    void transparencyLogAtiV1ToStringWorks() {
        TransparencyLogAtiV1 payload = new TransparencyLogAtiV1();
        payload.setAgentName("ati://v1.0.0.agent.example.com");
        payload.setAgentHost("agent.example.com");

        String str = payload.toString();
        assertThat(str).contains("ati://v1.0.0.agent.example.com");
        assertThat(str).contains("agent.example.com");
    }

    @Test
    @DisplayName("TransparencyLogAtiV1.Certificates toString should work")
    void transparencyLogAtiV1CertificatesToStringWorks() {
        TransparencyLogAtiV1.Certificates certs = new TransparencyLogAtiV1.Certificates();
        certs.setServerCertFingerprint("SHA-256:server");
        certs.setIdentityCertFingerprint("SHA-256:identity");

        String str = certs.toString();
        assertThat(str).contains("SHA-256:server");
        assertThat(str).contains("SHA-256:identity");
    }

    // ==================== TransparencyLog convenience methods (ATI-TL-V1) ====================

    @Test
    @DisplayName("TransparencyLog convenience methods should work with ATI-TL-V1 payload")
    void transparencyLogConvenienceMethodsShouldWorkWithAtiV1() {
        TransparencyLogAtiV1 payload = new TransparencyLogAtiV1();
        payload.setAgentName("ati://v1.0.0.agent.example.com");
        payload.setAgentHost("agent.example.com");
        payload.setVersion("1.0.0");
        payload.setAgentId("some-uuid");
        payload.setAgentStatus("ACTIVE");

        TransparencyLogAtiV1.Certificates certs = new TransparencyLogAtiV1.Certificates();
        certs.setServerCertFingerprint("SHA-256:server");
        certs.setIdentityCertFingerprint("SHA-256:identity");
        payload.setCertificates(certs);

        TransparencyLog log = new TransparencyLog();
        log.setStatus("ACTIVE");
        log.setSchemaVersion("ATI-TL-V1");
        log.setParsedPayload(payload);

        assertThat(log.getServerCertFingerprint()).isEqualTo("SHA-256:server");
        assertThat(log.getIdentityCertFingerprint()).isEqualTo("SHA-256:identity");
        assertThat(log.getAgentHost()).isEqualTo("agent.example.com");
        assertThat(log.getAtiName()).isEqualTo("ati://v1.0.0.agent.example.com");
    }

    @Test
    @DisplayName("TransparencyLog convenience methods return null when no payload")
    void transparencyLogConvenienceMethodsReturnNullWhenNoPayload() {
        TransparencyLog log = new TransparencyLog();

        assertThat(log.getServerCertFingerprint()).isNull();
        assertThat(log.getIdentityCertFingerprint()).isNull();
        assertThat(log.getAgentHost()).isNull();
        assertThat(log.getAtiName()).isNull();
    }

    @Test
    @DisplayName("TransparencyLog convenience methods return null when no certificates")
    void transparencyLogConvenienceMethodsReturnNullWhenNoCertificates() {
        TransparencyLogAtiV1 payload = new TransparencyLogAtiV1();
        payload.setAgentName("ati://v1.0.0.agent.example.com");
        // No certificates set

        TransparencyLog log = new TransparencyLog();
        log.setParsedPayload(payload);

        assertThat(log.getServerCertFingerprint()).isNull();
        assertThat(log.getIdentityCertFingerprint()).isNull();
        assertThat(log.getAtiName()).isEqualTo("ati://v1.0.0.agent.example.com");
    }

    @Test
    @DisplayName("CheckpointHistoryResponse getters and setters should work")
    void checkpointHistoryResponseGettersAndSettersWork() {
        CheckpointHistoryResponse response = new CheckpointHistoryResponse();
        CheckpointResponse checkpoint = new CheckpointResponse();
        PaginationInfo pagination = new PaginationInfo();

        response.setCheckpoints(List.of(checkpoint));
        response.setPagination(pagination);

        assertThat(response.getCheckpoints()).containsExactly(checkpoint);
        assertThat(response.getPagination()).isSameAs(pagination);
    }

    @Test
    @DisplayName("CheckpointHistoryResponse toString should work")
    void checkpointHistoryResponseToStringWorks() {
        CheckpointHistoryResponse response = new CheckpointHistoryResponse();
        CheckpointResponse checkpoint = new CheckpointResponse();
        response.setCheckpoints(List.of(checkpoint, checkpoint));

        String str = response.toString();
        assertThat(str).contains("2");
    }

    @Test
    @DisplayName("CheckpointHistoryResponse toString with null checkpoints")
    void checkpointHistoryResponseToStringWithNullCheckpoints() {
        CheckpointHistoryResponse response = new CheckpointHistoryResponse();

        String str = response.toString();
        assertThat(str).contains("0");
    }

    @Test
    @DisplayName("AgentAuditParams getters and setters should work")
    void agentAuditParamsGettersAndSettersWork() {
        AgentAuditParams params = new AgentAuditParams();

        params.setOffset(10);
        params.setLimit(25);

        assertThat(params.getOffset()).isEqualTo(10);
        assertThat(params.getLimit()).isEqualTo(25);
    }

    @Test
    @DisplayName("AgentAuditParams builder should work")
    void agentAuditParamsBuilderWorks() {
        AgentAuditParams params = AgentAuditParams.builder()
            .offset(10)
            .limit(25)
            .build();

        assertThat(params.getOffset()).isEqualTo(10);
        assertThat(params.getLimit()).isEqualTo(25);
    }
}
