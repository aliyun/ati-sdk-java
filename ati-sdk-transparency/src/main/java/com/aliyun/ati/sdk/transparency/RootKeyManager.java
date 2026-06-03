package com.aliyun.ati.sdk.transparency;

import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

import com.aliyun.ati.sdk.exception.AtiException;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.LoadingCache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Manages TL root public keys used for seal verification.
 *
 * <p>Wraps {@link AtiTransparencyClient#getRootKeys()} with a Caffeine cache
 * (24h TTL by default). Parses the JSON response containing PEM-encoded
 * public key(s) into {@link PublicKey} instances keyed by their key ID.
 */
public final class RootKeyManager {

    private static final Logger LOG = LoggerFactory.getLogger(RootKeyManager.class);
    private static final Duration DEFAULT_CACHE_TTL = Duration.ofHours(24);
    private static final String CACHE_KEY = "root-keys";

    private final AtiTransparencyClient transparencyClient;
    private final ObjectMapper objectMapper;
    private final LoadingCache<String, Map<String, PublicKey>> cache;

    /**
     * Creates a new RootKeyManager with the default 24h cache TTL.
     *
     * @param transparencyClient the transparency client to fetch root keys from
     */
    public RootKeyManager(AtiTransparencyClient transparencyClient) {
        this(transparencyClient, DEFAULT_CACHE_TTL);
    }

    /**
     * Creates a new RootKeyManager with a custom cache TTL.
     *
     * @param transparencyClient the transparency client to fetch root keys from
     * @param cacheTtl           the cache time-to-live duration
     */
    public RootKeyManager(AtiTransparencyClient transparencyClient, Duration cacheTtl) {
        this.transparencyClient = Objects.requireNonNull(
            transparencyClient, "transparencyClient must not be null");
        this.objectMapper = new ObjectMapper();
        this.cache = Caffeine.newBuilder()
            .expireAfterWrite(cacheTtl.toMillis(), TimeUnit.MILLISECONDS)
            .maximumSize(1)
            .build(key -> loadRootKeys());
    }

    /**
     * Returns the public key for the given key ID.
     *
     * @param keyId the key identifier
     * @return the parsed EC public key
     * @throws AtiException if no key is found for the given ID
     */
    public PublicKey getPublicKey(String keyId) {
        Objects.requireNonNull(keyId, "keyId must not be null");
        Map<String, PublicKey> keys = cache.get(CACHE_KEY);
        PublicKey key = keys.get(keyId);
        if (key == null) {
            throw new AtiException("No root key found for keyId: " + keyId);
        }
        return key;
    }

    private Map<String, PublicKey> loadRootKeys() {
        LOG.debug("Loading TL root keys");
        String response = transparencyClient.getRootKeys();
        try {
            List<RootKeyEntry> entries = objectMapper.readValue(
                response, new TypeReference<List<RootKeyEntry>>() { });
            Map<String, PublicKey> result = new HashMap<>();
            for (RootKeyEntry entry : entries) {
                PublicKey publicKey = parsePemPublicKey(entry.getPublicKey());
                result.put(entry.getKeyId(), publicKey);
                LOG.debug("Loaded root key: {}", entry.getKeyId());
            }
            return Collections.unmodifiableMap(result);
        } catch (AtiException e) {
            throw e;
        } catch (Exception e) {
            throw new AtiException("Failed to parse root keys", e);
        }
    }

    private static PublicKey parsePemPublicKey(String pem) throws Exception {
        String base64 = pem
            .replace("-----BEGIN PUBLIC KEY-----", "")
            .replace("-----END PUBLIC KEY-----", "")
            .replaceAll("\\s+", "");
        byte[] decoded = Base64.getDecoder().decode(base64);
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(decoded);
        KeyFactory keyFactory = KeyFactory.getInstance("EC");
        return keyFactory.generatePublic(keySpec);
    }

    /**
     * Jackson model for root key entries in the TL API response.
     */
    @JsonIgnoreProperties(ignoreUnknown = true)
    static final class RootKeyEntry {

        private String keyId;
        private String publicKey;

        public String getKeyId() {
            return keyId;
        }

        public void setKeyId(String keyId) {
            this.keyId = keyId;
        }

        public String getPublicKey() {
            return publicKey;
        }

        public void setPublicKey(String publicKey) {
            this.publicKey = publicKey;
        }
    }
}
