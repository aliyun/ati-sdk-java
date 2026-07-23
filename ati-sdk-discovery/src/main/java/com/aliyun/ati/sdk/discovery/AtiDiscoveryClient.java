package com.aliyun.ati.sdk.discovery;

import com.aliyun.ati.sdk.exception.AtiNotFoundException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Client for discovering ATI agents via DNS {@code _ati} TXT records on the Identity Hostname.
 *
 * <p>Example usage:</p>
 * <pre>{@code
 * AtiDiscoveryClient client = new AtiDiscoveryClient();
 *
 * AgentDetail detail = client.discover("abc123.bailian.aliyun.com", "^1.0.0");
 * String agentUrl = detail.getEndpoints().get(0).getAgentUrl();
 * }</pre>
 */
public final class AtiDiscoveryClient {

    private static final Logger LOG = LoggerFactory.getLogger(AtiDiscoveryClient.class);

    private final TxtRecordLookup txtLookup;

    /**
     * Creates a client with the default DNS TXT lookup (5s timeout).
     */
    public AtiDiscoveryClient() {
        this(new DnsTxtRecordLookup());
    }

    /**
     * Creates a client with a custom TXT lookup (for tests or custom resolvers).
     *
     * @param txtLookup TXT record lookup implementation
     */
    public AtiDiscoveryClient(TxtRecordLookup txtLookup) {
        this.txtLookup = Objects.requireNonNull(txtLookup, "txtLookup must not be null");
    }

    /**
     * Creates a client with a custom DNS timeout.
     *
     * @param timeout DNS lookup timeout
     */
    public AtiDiscoveryClient(Duration timeout) {
        this(new DnsTxtRecordLookup(timeout));
    }

    /**
     * Discovers an agent by Identity Hostname and optional version constraint.
     *
     * @param agentHost Identity Hostname (required)
     * @param versionConstraint optional SemVer constraint (e.g. {@code ^1.0.0})
     * @return discovered agent detail
     * @throws AtiNotFoundException if no matching TXT records are found
     * @throws DiscoveryException if DNS lookup fails
     */
    public AgentDetail discover(String agentHost, String versionConstraint) {
        Objects.requireNonNull(agentHost, "agentHost must not be null");
        LOG.debug("[Discovery] Resolving agent host '{}' (constraint='{}')", agentHost, versionConstraint);

        String dnsName = "_ati." + agentHost;
        List<String> txtValues = txtLookup.lookupTxt(dnsName);
        List<AtiDiscoveryRecord> records = parseRecords(txtValues);

        if (records.isEmpty()) {
            throw new AtiNotFoundException("Agent", agentHost);
        }

        String selectedVersion;
        try {
            selectedVersion = DiscoveryVersionSelector.selectLatestVersion(records, versionConstraint);
        } catch (IllegalArgumentException e) {
            throw new AtiNotFoundException("Agent", agentHost);
        }

        List<AtiDiscoveryRecord> selectedRecords = records.stream()
            .filter(r -> DiscoveryVersionSelector.versionsEqual(r.getAgentVersion(), selectedVersion))
            .toList();

        List<AgentEndpoint> endpoints = AgentDetail.toEndpoints(selectedRecords);

        AgentDetail detail = new AgentDetail();
        detail.setAgentHost(agentHost);
        detail.setAgentVersion(selectedVersion);
        detail.setEndpoints(endpoints);
        detail.setAccessHost(AgentDetail.extractAccessHost(endpoints));

        LOG.debug("[Discovery] Resolved {} — version='{}', endpoints={}",
            agentHost, selectedVersion, endpoints.size());
        return detail;
    }

    /**
     * Discovers an agent by Identity Hostname, selecting the latest {@code av}.
     *
     * @param agentHost Identity Hostname (required)
     * @return discovered agent detail
     */
    public AgentDetail discover(String agentHost) {
        return discover(agentHost, null);
    }

    private static List<AtiDiscoveryRecord> parseRecords(List<String> txtValues) {
        List<AtiDiscoveryRecord> parsed = new ArrayList<>();
        for (String txt : txtValues) {
            try {
                parsed.add(AtiDiscoveryRecord.parse(txt));
            } catch (IllegalArgumentException e) {
                LOG.debug("Skipping unparseable discovery TXT record: {}", e.getMessage());
            }
        }
        return parsed;
    }
}
