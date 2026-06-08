package com.aliyun.ati.sdk.discovery;

import java.net.UnknownHostException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Record;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.Type;

/**
 * DNS-based implementation of {@link AtiDiscoveryClient}.
 *
 * <p>Queries {@code _ati-badge.{host}} TXT records using dnsjava, parses all
 * records with {@link AtiBadgeRecord}, and matches the version from the
 * {@link AtiName} to build an {@link AtiAgentDescriptor}.
 *
 * <p>When multiple TXT records exist (multi-version), the record whose
 * {@code version} field matches the requested version is selected.
 */
public final class DnsAtiDiscoveryClient implements AtiDiscoveryClient {

    private static final Logger LOG = LoggerFactory.getLogger(DnsAtiDiscoveryClient.class);
    private static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(5);

    private final Duration timeout;

    public DnsAtiDiscoveryClient() {
        this(DEFAULT_TIMEOUT);
    }

    public DnsAtiDiscoveryClient(Duration timeout) {
        this.timeout = Objects.requireNonNull(timeout, "timeout must not be null");
    }

    @Override
    public AtiAgentDescriptor discover(AtiName name) {
        Objects.requireNonNull(name, "AtiName must not be null");
        String host = name.getAgentHost();
        String version = name.getVersion();

        String badgeUrl = null;
        String agentId = null;

        List<String> txtRecords = lookupAllTxt("_ati-badge." + host);
        AtiBadgeRecord matched = matchVersion(txtRecords, version);
        if (matched != null) {
            badgeUrl = matched.getUrl();
            agentId = matched.getAgentId();
        }

        return new AtiAgentDescriptor(host, version, badgeUrl, agentId);
    }

    private AtiBadgeRecord matchVersion(List<String> txtRecords, String version) {
        AtiBadgeRecord fallback = null;
        for (String txt : txtRecords) {
            try {
                AtiBadgeRecord badge = AtiBadgeRecord.parse(txt);
                String badgeVersion = badge.getVersion();
                if (versionsMatch(badgeVersion, version)) {
                    return badge;
                }
                if (fallback == null) {
                    fallback = badge;
                }
            } catch (Exception e) {
                LOG.debug("Skipping unparseable badge record: {}", e.getMessage());
            }
        }
        if (fallback != null) {
            LOG.debug("No exact version match for '{}', using first available: '{}'",
                version, fallback.getVersion());
        }
        return fallback;
    }

    private static boolean versionsMatch(String badgeVersion, String requestedVersion) {
        // badge version may have "v" prefix (e.g. "v1.0.0"), AtiName version does not (e.g. "1.0.0")
        String normalized = badgeVersion.startsWith("v") ? badgeVersion.substring(1) : badgeVersion;
        return normalized.equals(requestedVersion);
    }

    @SuppressWarnings("unchecked")
    private List<String> lookupAllTxt(String name) {
        List<String> results = new ArrayList<>();
        try {
            Lookup lookup = new Lookup(name, Type.TXT);
            SimpleResolver resolver = new SimpleResolver();
            resolver.setTimeout(timeout);
            lookup.setResolver(resolver);
            Record[] records = lookup.run();
            if (records == null || records.length == 0) {
                LOG.debug("No TXT record found for {}", name);
                return results;
            }
            for (Record record : records) {
                if (record instanceof TXTRecord txt) {
                    results.add(String.join("", txt.getStrings()));
                }
            }
            LOG.debug("Found {} TXT record(s) for {}", results.size(), name);
        } catch (UnknownHostException e) {
            LOG.warn("DNS resolver host not found for {}: {}", name, e.getMessage());
        } catch (Exception e) {
            LOG.warn("DNS lookup failed for {}: {}", name, e.getMessage());
        }
        return results;
    }
}
