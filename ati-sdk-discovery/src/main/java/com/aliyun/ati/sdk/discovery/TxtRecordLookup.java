package com.aliyun.ati.sdk.discovery;

import java.util.List;

/**
 * Looks up DNS TXT records for a name.
 */
public interface TxtRecordLookup {

    /**
     * Returns all TXT record string values for the given DNS name.
     *
     * @param dnsName fully qualified DNS name (e.g. {@code _ati.agent.example.com})
     * @return TXT values, empty if none
     */
    List<String> lookupTxt(String dnsName);
}
