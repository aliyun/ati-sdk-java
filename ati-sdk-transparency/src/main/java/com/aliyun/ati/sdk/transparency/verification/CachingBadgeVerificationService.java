package com.aliyun.ati.sdk.transparency.verification;

import java.util.Objects;
import java.util.concurrent.TimeUnit;

import com.github.benmanes.caffeine.cache.Cache;
import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Caching decorator for {@link BadgeVerificationService}.
 *
 * <p>Maintains two separate Caffeine caches (server and client) with
 * variable TTL: verified results are cached for 15 minutes, while
 * negative results expire after 5 minutes.
 */
public final class CachingBadgeVerificationService {

    private static final Logger LOG =
        LoggerFactory.getLogger(CachingBadgeVerificationService.class);
    private static final long POSITIVE_TTL_MINUTES = 15;
    private static final long NEGATIVE_TTL_MINUTES = 5;
    private static final int MAX_ENTRIES = 10_000;

    private final BadgeVerificationService delegate;
    private final Cache<String, ServerVerificationResult> serverCache;
    private final Cache<String, ClientVerificationResult> clientCache;

    /**
     * Creates a caching wrapper around the given delegate service.
     *
     * @param delegate the underlying verification service
     */
    public CachingBadgeVerificationService(BadgeVerificationService delegate) {
        this.delegate = Objects.requireNonNull(delegate,
            "delegate must not be null");
        this.serverCache = buildServerCache();
        this.clientCache = buildClientCache();
    }

    /**
     * Verifies a server's badge, returning a cached result when available.
     *
     * @param agentId the agent identifier
     * @return the server verification result
     */
    public ServerVerificationResult verifyServer(String agentId) {
        Objects.requireNonNull(agentId, "agentId must not be null");
        ServerVerificationResult cached = serverCache.getIfPresent(agentId);
        if (cached != null) {
            LOG.debug("Server verification cache hit for agent: {}",
                agentId);
            return cached;
        }
        ServerVerificationResult result = delegate.verifyServer(agentId);
        serverCache.put(agentId, result);
        return result;
    }

    /**
     * Verifies a client's badge, returning a cached result when available.
     *
     * @param agentId the agent identifier
     * @return the client verification result
     */
    public ClientVerificationResult verifyClient(String agentId) {
        Objects.requireNonNull(agentId, "agentId must not be null");
        ClientVerificationResult cached = clientCache.getIfPresent(agentId);
        if (cached != null) {
            LOG.debug("Client verification cache hit for agent: {}",
                agentId);
            return cached;
        }
        ClientVerificationResult result = delegate.verifyClient(agentId);
        clientCache.put(agentId, result);
        return result;
    }

    private static Cache<String, ServerVerificationResult> buildServerCache() {
        return Caffeine.newBuilder()
            .maximumSize(MAX_ENTRIES)
            .expireAfter(serverExpiry())
            .build();
    }

    private static Cache<String, ClientVerificationResult> buildClientCache() {
        return Caffeine.newBuilder()
            .maximumSize(MAX_ENTRIES)
            .expireAfter(clientExpiry())
            .build();
    }

    private static Expiry<String, ServerVerificationResult> serverExpiry() {
        return new Expiry<String, ServerVerificationResult>() {
            @Override
            public long expireAfterCreate(String key,
                                          ServerVerificationResult value,
                                          long currentTime) {
                return ttlNanos(value.getStatus());
            }

            @Override
            public long expireAfterUpdate(String key,
                                          ServerVerificationResult value,
                                          long currentTime,
                                          long currentDuration) {
                return currentDuration;
            }

            @Override
            public long expireAfterRead(String key,
                                        ServerVerificationResult value,
                                        long currentTime,
                                        long currentDuration) {
                return currentDuration;
            }
        };
    }

    private static Expiry<String, ClientVerificationResult> clientExpiry() {
        return new Expiry<String, ClientVerificationResult>() {
            @Override
            public long expireAfterCreate(String key,
                                          ClientVerificationResult value,
                                          long currentTime) {
                return ttlNanos(value.getStatus());
            }

            @Override
            public long expireAfterUpdate(String key,
                                          ClientVerificationResult value,
                                          long currentTime,
                                          long currentDuration) {
                return currentDuration;
            }

            @Override
            public long expireAfterRead(String key,
                                        ClientVerificationResult value,
                                        long currentTime,
                                        long currentDuration) {
                return currentDuration;
            }
        };
    }

    private static long ttlNanos(VerificationStatus status) {
        long minutes = status == VerificationStatus.VERIFIED
            ? POSITIVE_TTL_MINUTES
            : NEGATIVE_TTL_MINUTES;
        return TimeUnit.MINUTES.toNanos(minutes);
    }
}
