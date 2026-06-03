package com.aliyun.ati.sdk.transparency.verification;

import java.util.Collections;
import java.util.List;

import com.aliyun.ati.sdk.transparency.model.MerkleProof;
import com.fasterxml.jackson.databind.ObjectMapper;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class MerkleProofVerifierTest {

    private MerkleProofVerifier verifier;

    @BeforeEach
    void setUp() {
        verifier = new MerkleProofVerifier();
    }

    @Test
    void shouldVerifySingleElementTree() throws Exception {
        // Tree with 1 leaf: root = leafHash, empty path
        byte[] leaf = "leaf-data".getBytes();
        byte[] leafHash = MerkleProofVerifier.hashLeaf(leaf);
        String leafHex = bytesToHex(leafHash);

        MerkleProof proof = buildProof(leafHex, 0, 1, Collections.emptyList(), leafHex);

        assertThat(verifier.verify(proof)).isTrue();
    }

    @Test
    void shouldVerifyTwoElementTree() throws Exception {
        // Tree: root = H(leaf0 || leaf1)
        byte[] leaf0 = MerkleProofVerifier.hashLeaf("data0".getBytes());
        byte[] leaf1 = MerkleProofVerifier.hashLeaf("data1".getBytes());
        byte[] root = MerkleProofVerifier.hashNode(leaf0, leaf1);

        // Prove leaf0 (index=0): sibling is leaf1
        MerkleProof proof = buildProof(bytesToHex(leaf0), 0, 2,
            List.of(bytesToHex(leaf1)), bytesToHex(root));
        assertThat(verifier.verify(proof)).isTrue();

        // Prove leaf1 (index=1): sibling is leaf0
        MerkleProof proof2 = buildProof(bytesToHex(leaf1), 1, 2,
            List.of(bytesToHex(leaf0)), bytesToHex(root));
        assertThat(verifier.verify(proof2)).isTrue();
    }

    @Test
    void shouldVerifyFourElementBalancedTree() throws Exception {
        // Tree:        root
        //           /        \
        //      node01       node23
        //      /   \        /   \
        //   leaf0 leaf1  leaf2 leaf3
        byte[] leaf0 = MerkleProofVerifier.hashLeaf("d0".getBytes());
        byte[] leaf1 = MerkleProofVerifier.hashLeaf("d1".getBytes());
        byte[] leaf2 = MerkleProofVerifier.hashLeaf("d2".getBytes());
        byte[] leaf3 = MerkleProofVerifier.hashLeaf("d3".getBytes());
        byte[] node01 = MerkleProofVerifier.hashNode(leaf0, leaf1);
        byte[] node23 = MerkleProofVerifier.hashNode(leaf2, leaf3);
        byte[] root = MerkleProofVerifier.hashNode(node01, node23);

        // Prove leaf2 (index=2): path = [leaf3, node01]
        MerkleProof proof = buildProof(
            bytesToHex(leaf2), 2, 4,
            List.of(bytesToHex(leaf3), bytesToHex(node01)),
            bytesToHex(root));
        assertThat(verifier.verify(proof)).isTrue();
    }

    @Test
    void shouldRejectWrongRootHash() throws Exception {
        byte[] leaf0 = MerkleProofVerifier.hashLeaf("data0".getBytes());
        byte[] leaf1 = MerkleProofVerifier.hashLeaf("data1".getBytes());

        MerkleProof proof = buildProof(
            bytesToHex(leaf0), 0, 2,
            List.of(bytesToHex(leaf1)),
            "0000000000000000000000000000000000000000000000000000000000000000");
        assertThat(verifier.verify(proof)).isFalse();
    }

    @Test
    void shouldRejectIncorrectPath() throws Exception {
        byte[] leaf0 = MerkleProofVerifier.hashLeaf("data0".getBytes());
        byte[] leaf1 = MerkleProofVerifier.hashLeaf("data1".getBytes());
        byte[] root = MerkleProofVerifier.hashNode(leaf0, leaf1);

        // Provide wrong sibling
        MerkleProof proof = buildProof(
            bytesToHex(leaf0), 0, 2,
            List.of("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"),
            bytesToHex(root));
        assertThat(verifier.verify(proof)).isFalse();
    }

    private MerkleProof buildProof(String leafHash, long leafIndex, long treeSize,
                                   List<String> path, String rootHash) throws Exception {
        ObjectMapper mapper = new ObjectMapper();
        String pathJson = mapper.writeValueAsString(path);
        String json = String.format(
            "{\"leafHash\":\"%s\",\"leafIndex\":%d,\"treeSize\":%d,\"treeVersion\":1,\"path\":%s,\"rootHash\":\"%s\"}",
            leafHash, leafIndex, treeSize, pathJson, rootHash);
        return mapper.readValue(json, MerkleProof.class);
    }

    private static String bytesToHex(byte[] bytes) {
        char[] hex = "0123456789abcdef".toCharArray();
        char[] result = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            result[i * 2] = hex[(bytes[i] >> 4) & 0x0F];
            result[i * 2 + 1] = hex[bytes[i] & 0x0F];
        }
        return new String(result);
    }
}
