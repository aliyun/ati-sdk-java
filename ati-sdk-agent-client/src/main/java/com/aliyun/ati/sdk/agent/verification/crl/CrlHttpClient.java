package com.aliyun.ati.sdk.agent.verification.crl;

import java.io.IOException;
import java.net.URI;

/**
 * Fetches raw CRL bytes from a CDP URI.
 */
@FunctionalInterface
public interface CrlHttpClient {

    /**
     * Performs an HTTP GET for the CRL at the given URI.
     *
     * @param uri CDP URI
     * @return DER-encoded CRL bytes
     * @throws IOException if the fetch fails
     */
    byte[] fetch(URI uri) throws IOException;
}
