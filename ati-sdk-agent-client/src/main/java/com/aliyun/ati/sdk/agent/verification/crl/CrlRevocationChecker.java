package com.aliyun.ati.sdk.agent.verification.crl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.Objects;
import java.util.Optional;

/**
 * Orchestrates CDP discovery, CRL fetch, signature validation, and serial revocation lookup.
 */
public final class CrlRevocationChecker {

    private static final Logger LOGGER = LoggerFactory.getLogger(CrlRevocationChecker.class);

    private final CrlFetcher crlFetcher;
    private final CrlValidator crlValidator;

    public CrlRevocationChecker(CrlFetcher crlFetcher) {
        this(crlFetcher, new CrlValidator());
    }

    CrlRevocationChecker(CrlFetcher crlFetcher, CrlValidator crlValidator) {
        this.crlFetcher = Objects.requireNonNull(crlFetcher, "crlFetcher");
        this.crlValidator = Objects.requireNonNull(crlValidator, "crlValidator");
    }

    /**
     * Checks whether the client Identity Certificate has been revoked via CRL.
     *
     * @param clientCert client leaf certificate
     * @param chain      presented certificate chain (index 0 = client leaf)
     * @return revocation check outcome
     */
    public CrlRevocationResult check(X509Certificate clientCert, X509Certificate[] chain) {
        Objects.requireNonNull(clientCert, "clientCert");
        Objects.requireNonNull(chain, "chain");

        CdpExtractor.CdpLookupResult cdpLookup = CdpExtractor.resolveFirstCdpUri(chain);
        if (cdpLookup.isSkipped()) {
            return CrlRevocationResult.skipped();
        }
        if (cdpLookup.isFailed()) {
            return CrlRevocationResult.failed(cdpLookup.failureMessage(), null);
        }

        URI cdpUri = cdpLookup.cdpUri();
        Optional<X509Certificate> issuingCaOpt = CdpExtractor.findIssuingCa(clientCert, chain);
        if (issuingCaOpt.isEmpty()) {
            return CrlRevocationResult.failed("Cannot determine issuing CA for CRL validation", cdpUri);
        }

        X509Certificate issuingCa = issuingCaOpt.get();
        try {
            byte[] crlBytes = crlFetcher.fetch(cdpUri);
            crlValidator.validateNotRevoked(crlBytes, issuingCa, clientCert.getSerialNumber());
            LOGGER.debug("CRL check passed for serial {} via {}", clientCert.getSerialNumber(), cdpUri);
            return CrlRevocationResult.passed(cdpUri);
        } catch (CrlValidator.CrlValidationException e) {
            if (e.isRevoked()) {
                return CrlRevocationResult.revoked(cdpUri);
            }
            LOGGER.warn("CRL validation failed for {}: {}", cdpUri, e.getMessage());
            return CrlRevocationResult.failed(e.getMessage(), cdpUri);
        } catch (IOException e) {
            LOGGER.warn("CRL fetch failed for {}: {}", cdpUri, e.getMessage());
            return CrlRevocationResult.failed("CRL fetch failed: " + e.getMessage(), cdpUri);
        }
    }
}
