package com.aliyun.ati.sdk.transparency.verification;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.Objects;

import com.aliyun.ati.sdk.transparency.model.MerkleProof;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * RFC 9162 Merkle inclusion proof verification.
 *
 * <p>Verifies that a leaf is included in a Merkle tree given an audit path.
 * Uses SHA-256 with domain-separated hashing: leaves are prefixed with 0x00,
 * internal nodes with 0x01.
 */
public final class MerkleProofVerifier {

    private static final Logger LOG = LoggerFactory.getLogger(MerkleProofVerifier.class);
    private static final byte LEAF_PREFIX = 0x00;
    private static final byte NODE_PREFIX = 0x01;

    /**
     * Verifies a Merkle inclusion proof.
     *
     * @param proof the Merkle proof containing leaf hash, path, and expected root
     * @return {@code true} if the proof is valid, {@code false} otherwise
     */
    public boolean verify(MerkleProof proof) {
        Objects.requireNonNull(proof, "proof must not be null");
        try {
            byte[] computedHash = hexToBytes(proof.getLeafHash());
            long index = proof.getLeafIndex();
            List<String> path = proof.getPath();

            for (String pathElement : path) {
                byte[] sibling = hexToBytes(pathElement);
                if (index % 2 == 0) {
                    computedHash = hashNode(computedHash, sibling);
                } else {
                    computedHash = hashNode(sibling, computedHash);
                }
                index = index / 2;
            }

            byte[] expectedRoot = hexToBytes(proof.getRootHash());
            boolean valid = MessageDigest.isEqual(computedHash, expectedRoot);
            if (!valid) {
                LOG.warn("Merkle proof verification failed: computed root does not match expected");
            }
            return valid;
        } catch (Exception e) {
            LOG.error("Merkle proof verification error", e);
            return false;
        }
    }

    static byte[] hashNode(byte[] left, byte[] right) {
        MessageDigest digest = sha256();
        digest.update(NODE_PREFIX);
        digest.update(left);
        digest.update(right);
        return digest.digest();
    }

    static byte[] hashLeaf(byte[] data) {
        MessageDigest digest = sha256();
        digest.update(LEAF_PREFIX);
        digest.update(data);
        return digest.digest();
    }

    private static MessageDigest sha256() {
        try {
            return MessageDigest.getInstance("SHA-256");
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
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
