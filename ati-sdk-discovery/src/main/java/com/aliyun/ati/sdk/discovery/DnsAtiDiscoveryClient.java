package com.aliyun.ati.sdk.discovery;

import java.net.UnknownHostException;
import java.time.Duration;
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
 * <p>Queries {@code _ati-badge.{host}} TXT records using dnsjava, parses the result
 * with {@link AtiBadgeRecord}, and builds an {@link AtiAgentDescriptor}.
 */
public final class DnsAtiDiscoveryClient implements AtiDiscoveryClient {

    private static final Logger LOG = LoggerFactory.getLogger(DnsAtiDiscoveryClient.class);
    private static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(5);

    private final Duration timeout;

    /**
     * Creates a client with the default timeout of 5 seconds.
     */
    public DnsAtiDiscoveryClient() {
        this(DEFAULT_TIMEOUT);
    }

    /**
     * Creates a client with a custom timeout.
     *
     * @param timeout the DNS lookup timeout
     */
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

        String badgeTxt = lookupTxt("_ati-badge." + host);
        if (badgeTxt != null) {
            AtiBadgeRecord badge = AtiBadgeRecord.parse(badgeTxt);
            badgeUrl = badge.getUrl();
            agentId = badge.getAgentId();
        }

        return new AtiAgentDescriptor(host, version, badgeUrl, agentId);
    }

    @SuppressWarnings("unchecked")
    private String lookupTxt(String name) {
        try {
            Lookup lookup = new Lookup(name, Type.TXT);
            SimpleResolver resolver = new SimpleResolver();
            resolver.setTimeout(timeout);
            lookup.setResolver(resolver);
            Record[] records = lookup.run();
            if (records == null || records.length == 0) {
                LOG.debug("No TXT record found for {}", name);
                return null;
            }
            TXTRecord txt = (TXTRecord) records[0];
            return String.join("", txt.getStrings());
        } catch (UnknownHostException e) {
            LOG.warn("DNS resolver host not found for {}: {}", name, e.getMessage());
            return null;
        } catch (Exception e) {
            LOG.warn("DNS lookup failed for {}: {}", name, e.getMessage());
            return null;
        }
    }
}
