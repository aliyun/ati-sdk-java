package com.aliyun.ati.sdk.discovery;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Record;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.TXTRecord;
import org.xbill.DNS.Type;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * DNS TXT lookup using dnsjava.
 */
public final class DnsTxtRecordLookup implements TxtRecordLookup {

    private static final Logger LOG = LoggerFactory.getLogger(DnsTxtRecordLookup.class);

    private final Duration timeout;

    public DnsTxtRecordLookup() {
        this(Duration.ofSeconds(5));
    }

    public DnsTxtRecordLookup(Duration timeout) {
        this.timeout = Objects.requireNonNull(timeout, "timeout must not be null");
    }

    @Override
    public List<String> lookupTxt(String dnsName) {
        Objects.requireNonNull(dnsName, "dnsName must not be null");
        List<String> results = new ArrayList<>();
        try {
            Lookup lookup = new Lookup(dnsName, Type.TXT);
            SimpleResolver resolver = new SimpleResolver();
            resolver.setTimeout(timeout);
            lookup.setResolver(resolver);
            Record[] records = lookup.run();
            if (records == null || records.length == 0) {
                LOG.debug("No TXT records for {}", dnsName);
                return results;
            }
            for (Record record : records) {
                if (record instanceof TXTRecord txt) {
                    results.add(String.join("", txt.getStrings()));
                }
            }
            LOG.debug("Found {} TXT record(s) for {}", results.size(), dnsName);
        } catch (Exception e) {
            LOG.warn("DNS TXT lookup failed for {}: {}", dnsName, e.getMessage());
            throw new DiscoveryException("DNS TXT lookup failed for " + dnsName, e);
        }
        return results;
    }
}
