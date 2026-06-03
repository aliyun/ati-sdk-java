package com.aliyun.ati.sdk.transparency.model;

import java.util.List;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

@JsonIgnoreProperties(ignoreUnknown = true)
public final class MerkleProof {

    private String leafHash;
    private long leafIndex;
    private long treeSize;
    private long treeVersion;
    private List<String> path;
    private String rootHash;

    private MerkleProof() {
    }

    public String getLeafHash() {
        return leafHash;
    }

    public long getLeafIndex() {
        return leafIndex;
    }

    public long getTreeSize() {
        return treeSize;
    }

    public long getTreeVersion() {
        return treeVersion;
    }

    public List<String> getPath() {
        return path;
    }

    public String getRootHash() {
        return rootHash;
    }
}
