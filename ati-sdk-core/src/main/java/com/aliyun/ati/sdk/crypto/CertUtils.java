package com.aliyun.ati.sdk.crypto;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Objects;

public final class CertUtils {

    private static final char[] HEX = "0123456789abcdef".toCharArray();

    private CertUtils() { }

    public static String sha256Fingerprint(X509Certificate cert) {
        Objects.requireNonNull(cert, "Certificate must not be null");
        try {
            return "SHA-256:" + sha256Hex(cert.getEncoded());
        } catch (CertificateEncodingException e) {
            throw new IllegalStateException("Failed to encode certificate", e);
        }
    }

    public static String sha256Hex(byte[] data) {
        Objects.requireNonNull(data, "Data must not be null");
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] hash = digest.digest(data);
            return bytesToHex(hash);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 not available", e);
        }
    }

    public static boolean fingerprintMatches(String a, String b) {
        if (a == null || b == null) {
            return false;
        }
        return MessageDigest.isEqual(
                a.getBytes(StandardCharsets.UTF_8),
                b.getBytes(StandardCharsets.UTF_8));
    }

    private static String bytesToHex(byte[] bytes) {
        char[] hex = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            hex[i * 2] = HEX[(bytes[i] >> 4) & 0x0F];
            hex[i * 2 + 1] = HEX[bytes[i] & 0x0F];
        }
        return new String(hex);
    }
}
