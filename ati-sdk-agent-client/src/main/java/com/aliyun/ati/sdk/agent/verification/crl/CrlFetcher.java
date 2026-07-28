package com.aliyun.ati.sdk.agent.verification.crl;

import com.github.benmanes.caffeine.cache.Caffeine;
import com.github.benmanes.caffeine.cache.Expiry;
import com.github.benmanes.caffeine.cache.LoadingCache;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.security.cert.X509CRL;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.Objects;
import java.util.concurrent.TimeUnit;

/**
 * Fetches and caches CRLs per CDP URI.
 *
 * <p>Cache expiry follows the CRL {@code nextUpdate}, capped at {@link #MAX_CACHE_AGE}.</p>
 */
public final class CrlFetcher {

    static final Duration MAX_CACHE_AGE = Duration.ofHours(12);

    private static final Logger LOGGER = LoggerFactory.getLogger(CrlFetcher.class);

    private final CrlHttpClient httpClient;
    private final CrlValidator crlValidator;
    private final Duration maxCacheAge;
    private final LoadingCache<URI, CachedCrl> cache;

    public CrlFetcher(CrlHttpClient httpClient) {
        this(httpClient, new CrlValidator(), MAX_CACHE_AGE);
    }

    CrlFetcher(CrlHttpClient httpClient, CrlValidator crlValidator) {
        this(httpClient, crlValidator, MAX_CACHE_AGE);
    }

    CrlFetcher(CrlHttpClient httpClient, CrlValidator crlValidator, Duration maxCacheAge) {
        this.httpClient = Objects.requireNonNull(httpClient, "httpClient");
        this.crlValidator = Objects.requireNonNull(crlValidator, "crlValidator");
        this.maxCacheAge = Objects.requireNonNull(maxCacheAge, "maxCacheAge");
        this.cache = Caffeine.newBuilder()
            .expireAfter(new CrlCacheExpiry())
            .build(this::load);
    }

    /**
     * Returns cached or freshly fetched CRL bytes for the CDP URI.
     */
    public byte[] fetch(URI cdpUri) throws IOException {
        Objects.requireNonNull(cdpUri, "cdpUri");
        try {
            return cache.get(cdpUri).crlBytes();
        } catch (RuntimeException e) {
            Throwable cause = e.getCause() != null ? e.getCause() : e;
            if (cause instanceof IOException io) {
                throw io;
            }
            throw new IOException("Failed to fetch CRL from " + cdpUri, cause);
        }
    }

    /**
     * Invalidates a cached CRL entry (for tests).
     */
    void invalidate(URI cdpUri) {
        cache.invalidate(cdpUri);
    }

    /**
     * Exposes cache expiry calculation for tests.
     */
    static Duration computeCacheTtl(X509CRL crl, Instant fetchedAt) {
        return computeCacheTtl(crl, fetchedAt, MAX_CACHE_AGE);
    }

    static Duration computeCacheTtl(X509CRL crl, Instant fetchedAt, Duration maxCacheAge) {
        Instant maxStaleAt = fetchedAt.plus(maxCacheAge);
        Date nextUpdate = crl.getNextUpdate();
        if (nextUpdate == null) {
            return maxCacheAge;
        }
        Instant nextUpdateInstant = nextUpdate.toInstant();
        if (!nextUpdateInstant.isAfter(fetchedAt)) {
            return Duration.ZERO;
        }
        Duration untilNextUpdate = Duration.between(fetchedAt, nextUpdateInstant);
        Duration untilMaxStale = Duration.between(fetchedAt, maxStaleAt);
        return untilNextUpdate.compareTo(untilMaxStale) <= 0 ? untilNextUpdate : untilMaxStale;
    }

    private CachedCrl load(URI cdpUri) throws IOException {
        LOGGER.debug("Fetching CRL from {}", cdpUri);
        byte[] bytes = httpClient.fetch(cdpUri);
        try {
            X509CRL crl = crlValidator.parse(bytes);
            Instant fetchedAt = Instant.now();
            Duration ttl = computeCacheTtl(crl, fetchedAt, maxCacheAge);
            return new CachedCrl(bytes, fetchedAt, ttl);
        } catch (CrlValidator.CrlValidationException e) {
            throw new IOException("Fetched bytes are not a valid CRL", e);
        }
    }

    record CachedCrl(byte[] crlBytes, Instant fetchedAt, Duration ttl) {
        CachedCrl {
            Objects.requireNonNull(crlBytes, "crlBytes");
            Objects.requireNonNull(fetchedAt, "fetchedAt");
            Objects.requireNonNull(ttl, "ttl");
        }
    }

    private static final class CrlCacheExpiry implements Expiry<URI, CachedCrl> {

        @Override
        public long expireAfterCreate(URI key, CachedCrl value, long currentTime) {
            return toNanos(value.ttl());
        }

        @Override
        public long expireAfterUpdate(URI key, CachedCrl value, long currentTime, long currentDuration) {
            return expireAfterCreate(key, value, currentTime);
        }

        @Override
        public long expireAfterRead(URI key, CachedCrl value, long currentTime, long currentDuration) {
            return currentDuration;
        }

        private static long toNanos(Duration ttl) {
            long nanos = ttl.toNanos();
            return nanos <= 0 ? TimeUnit.MILLISECONDS.toNanos(1) : nanos;
        }
    }
}
