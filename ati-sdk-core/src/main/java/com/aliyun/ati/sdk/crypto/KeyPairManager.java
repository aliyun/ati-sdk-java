package com.aliyun.ati.sdk.crypto;

import java.io.FileReader;
import java.io.IOException;
import java.io.StringWriter;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Utility class for generating and managing cryptographic key pairs.
 *
 * <p>This class provides methods for generating RSA and EC key pairs
 * suitable for use with ATI certificate requests.</p>
 *
 * <p>This is a lightweight implementation using only JDK classes.
 * For advanced PEM parsing with encrypted keys, consider using
 * BouncyCastle-based utilities.</p>
 *
 * <p>Example usage:</p>
 * <pre>{@code
 * KeyPairManager keyManager = new KeyPairManager();
 * KeyPair identityKeyPair = keyManager.generateRsaKeyPair(2048);
 * KeyPair serverKeyPair = keyManager.generateRsaKeyPair(2048);
 * }</pre>
 */
public class KeyPairManager {

    private static final Pattern PEM_PRIVATE_KEY_PATTERN = Pattern.compile(
        "-----BEGIN (?:RSA |EC )?PRIVATE KEY-----\\s*([A-Za-z0-9+/\\s=]+)\\s*-----END (?:RSA |EC )?PRIVATE KEY-----",
        Pattern.DOTALL);

    /**
     * Creates a new KeyPairManager instance.
     */
    public KeyPairManager() {
        // Default constructor
    }

    /**
     * Generates an RSA key pair with the specified key size.
     *
     * @param keySize the key size in bits (typically 2048 or 4096)
     * @return the generated key pair
     * @throws IllegalArgumentException if the key size is invalid
     * @throws RuntimeException if key generation fails
     */
    public KeyPair generateRsaKeyPair(int keySize) {
        if (keySize < 2048) {
            throw new IllegalArgumentException("RSA key size must be at least 2048 bits");
        }

        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
            keyGen.initialize(keySize);
            return keyGen.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to generate RSA key pair", e);
        }
    }

    /**
     * Generates an RSA key pair with default key size (2048 bits).
     *
     * @return the generated key pair
     * @throws RuntimeException if key generation fails
     */
    public KeyPair generateRsaKeyPair() {
        return generateRsaKeyPair(2048);
    }

    /**
     * Generates an EC (Elliptic Curve) key pair using the specified curve.
     *
     * @param curveName the curve name (e.g., "secp256r1", "secp384r1")
     * @return the generated key pair
     * @throws IllegalArgumentException if the curve name is invalid
     * @throws RuntimeException if key generation fails
     */
    public KeyPair generateEcKeyPair(String curveName) {
        if (curveName == null || curveName.isBlank()) {
            throw new IllegalArgumentException("Curve name cannot be null or blank");
        }

        try {
            KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
            keyGen.initialize(new ECGenParameterSpec(curveName));
            return keyGen.generateKeyPair();
        } catch (Exception e) {
            throw new RuntimeException("Failed to generate EC key pair with curve: " + curveName, e);
        }
    }

    /**
     * Generates an EC key pair using the P-256 curve (secp256r1).
     *
     * @return the generated key pair
     * @throws RuntimeException if key generation fails
     */
    public KeyPair generateEcKeyPair() {
        return generateEcKeyPair("secp256r1");
    }

    /**
     * Loads a key pair from a PEM file containing an unencrypted PKCS#8 private key.
     *
     * <p>The public key is derived from the private key. Only unencrypted keys
     * are supported by this implementation. For encrypted keys, use BouncyCastle.</p>
     *
     * @param filePath the path to the PEM file
     * @param password the password (currently ignored; for API compatibility)
     * @return the loaded key pair
     * @throws RuntimeException if loading fails
     */
    public KeyPair loadKeyPairFromPem(Path filePath, String password) {
        if (filePath == null) {
            throw new IllegalArgumentException("File path cannot be null");
        }
        if (!Files.exists(filePath)) {
            throw new IllegalArgumentException("PEM file does not exist: " + filePath);
        }

        try {
            String pemContent = Files.readString(filePath);
            return loadKeyPairFromPemString(pemContent);
        } catch (IOException e) {
            throw new RuntimeException("Failed to load key pair from PEM file: " + filePath, e);
        }
    }

    /**
     * Loads a key pair from a PEM file (convenience method with String path).
     *
     * @param filePath the path to the PEM file
     * @param password the password (currently ignored; for API compatibility)
     * @return the loaded key pair
     * @throws RuntimeException if loading fails
     */
    public KeyPair loadKeyPairFromPem(String filePath, String password) {
        return loadKeyPairFromPem(Path.of(filePath), password);
    }

    /**
     * Loads a key pair from a PEM string containing a PKCS#8 private key.
     */
    private KeyPair loadKeyPairFromPemString(String pem) {
        Matcher matcher = PEM_PRIVATE_KEY_PATTERN.matcher(pem);
        if (!matcher.find()) {
            throw new RuntimeException("No private key found in PEM content");
        }

        String base64 = matcher.group(1).replaceAll("\\s+", "");
        byte[] derBytes = Base64.getDecoder().decode(base64);

        try {
            // Try RSA first, then EC
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(derBytes);
            PrivateKey privateKey;
            PublicKey publicKey;

            try {
                KeyFactory kf = KeyFactory.getInstance("RSA");
                privateKey = kf.generatePrivate(keySpec);
                java.security.interfaces.RSAPrivateCrtKey rsaKey =
                    (java.security.interfaces.RSAPrivateCrtKey) privateKey;
                java.security.spec.RSAPublicKeySpec pubSpec =
                    new java.security.spec.RSAPublicKeySpec(
                        rsaKey.getModulus(), rsaKey.getPublicExponent());
                publicKey = kf.generatePublic(pubSpec);
            } catch (Exception rsaEx) {
                try {
                    KeyFactory kf = KeyFactory.getInstance("EC");
                    privateKey = kf.generatePrivate(keySpec);
                    // For EC, we cannot easily derive the public key without BouncyCastle
                    // Return null public key - caller should use the private key directly
                    publicKey = null;
                } catch (Exception ecEx) {
                    throw new RuntimeException(
                        "Failed to parse private key as RSA or EC", ecEx);
                }
            }

            return new KeyPair(publicKey, privateKey);
        } catch (RuntimeException e) {
            throw e;
        } catch (Exception e) {
            throw new RuntimeException("Failed to load key pair from PEM", e);
        }
    }

    /**
     * Gets a private key as an unencrypted PEM-formatted string (PKCS#8).
     *
     * @param keyPair the key pair containing the private key
     * @return the private key in PEM format (unencrypted)
     * @throws RuntimeException if conversion fails
     */
    public String getPrivateKeyAsPem(KeyPair keyPair) {
        return getPrivateKeyAsPem(keyPair, null);
    }

    /**
     * Gets a private key as a PEM-formatted string.
     *
     * <p>Note: password-based encryption is not supported in this lightweight
     * implementation. The password parameter is accepted for API compatibility
     * but is currently ignored.</p>
     *
     * @param keyPair the key pair containing the private key
     * @param password optional password (currently ignored)
     * @return the private key in PEM format
     * @throws RuntimeException if conversion fails
     */
    public String getPrivateKeyAsPem(KeyPair keyPair, String password) {
        if (keyPair == null) {
            throw new IllegalArgumentException("Key pair cannot be null");
        }

        byte[] encoded = keyPair.getPrivate().getEncoded();
        String base64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(encoded);
        return "-----BEGIN PRIVATE KEY-----\n" + base64 + "\n-----END PRIVATE KEY-----\n";
    }
}
