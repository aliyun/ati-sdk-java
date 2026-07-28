package com.aliyun.ati.sdk.agent.verification.crl;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@DisplayName("CrlFetcher")
class CrlFetcherTest {

    @Test
    @DisplayName("caches CRL until nextUpdate when sooner than 12h")
    void cachesUntilNextUpdate() throws Exception {
        CrlTestFixtures.TestCa ca = CrlTestFixtures.createTestCa("http://crl.example.test/cache.crl");
        Instant nextUpdate = Instant.now().plus(2, ChronoUnit.HOURS);
        byte[] crlBytes = CrlTestFixtures.createCrlBytes(ca, nextUpdate, Set.of());
        AtomicInteger fetchCount = new AtomicInteger();

        CrlHttpClient httpClient = uri -> {
            fetchCount.incrementAndGet();
            return crlBytes;
        };
        CrlFetcher fetcher = new CrlFetcher(httpClient);
        URI cdpUri = URI.create("http://crl.example.test/cache.crl");

        assertThat(fetcher.fetch(cdpUri)).isEqualTo(crlBytes);
        assertThat(fetcher.fetch(cdpUri)).isEqualTo(crlBytes);
        assertThat(fetchCount).hasValue(1);
    }

    @Test
    @DisplayName("caps cache TTL at 12 hours when nextUpdate is later")
    void capsCacheAtTwelveHours() throws Exception {
        CrlTestFixtures.TestCa ca = CrlTestFixtures.createTestCa("http://crl.example.test/long.crl");
        Instant nextUpdate = Instant.now().plus(48, ChronoUnit.HOURS);
        var crl = CrlTestFixtures.createCrl(ca, nextUpdate, Set.of());

        Duration ttl = CrlFetcher.computeCacheTtl(crl, Instant.now());

        assertThat(ttl).isLessThanOrEqualTo(CrlFetcher.MAX_CACHE_AGE);
        assertThat(ttl).isGreaterThan(Duration.ofHours(11));
    }

    @Test
    @DisplayName("forces immediate refresh when nextUpdate is in the past")
    void refreshesWhenNextUpdateExpired() throws Exception {
        CrlTestFixtures.TestCa ca = CrlTestFixtures.createTestCa("http://crl.example.test/no-next.crl");
        Instant pastNextUpdate = Instant.now().minus(1, ChronoUnit.HOURS);
        byte[] crlBytes = CrlTestFixtures.createCrlBytes(ca, pastNextUpdate, Set.of());
        var crl = new CrlValidator().parse(crlBytes);

        Duration ttl = CrlFetcher.computeCacheTtl(crl, Instant.now());

        assertThat(ttl).isEqualTo(Duration.ZERO);
    }

    @Test
    @DisplayName("propagates HTTP fetch failures")
    void propagatesFetchFailures() {
        CrlHttpClient httpClient = uri -> {
            throw new java.io.IOException("connection refused");
        };
        CrlFetcher fetcher = new CrlFetcher(httpClient);

        assertThatThrownBy(() -> fetcher.fetch(URI.create("http://crl.example.test/down.crl")))
            .isInstanceOf(java.io.IOException.class)
            .hasMessageContaining("connection refused");
    }

    @Test
    @DisplayName("refetches CRL after max cache age expires")
    void refetchesAfterMaxCacheAgeExpires() throws Exception {
        CrlTestFixtures.TestCa ca = CrlTestFixtures.createTestCa("http://crl.example.test/refresh.crl");
        Instant nextUpdate = Instant.now().plus(48, ChronoUnit.HOURS);
        byte[] crlBytes = CrlTestFixtures.createCrlBytes(ca, nextUpdate, Set.of());
        AtomicInteger fetchCount = new AtomicInteger();

        CrlHttpClient httpClient = uri -> {
            fetchCount.incrementAndGet();
            return crlBytes;
        };
        CrlFetcher fetcher = new CrlFetcher(httpClient, new CrlValidator(), Duration.ofMillis(50));
        URI cdpUri = URI.create("http://crl.example.test/refresh.crl");

        assertThat(fetcher.fetch(cdpUri)).isEqualTo(crlBytes);
        assertThat(fetcher.fetch(cdpUri)).isEqualTo(crlBytes);
        assertThat(fetchCount).hasValue(1);

        Thread.sleep(100);

        assertThat(fetcher.fetch(cdpUri)).isEqualTo(crlBytes);
        assertThat(fetchCount).hasValue(2);
    }
}
