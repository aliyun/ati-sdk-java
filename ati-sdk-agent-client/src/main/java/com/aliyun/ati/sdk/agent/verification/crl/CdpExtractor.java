package com.aliyun.ati.sdk.agent.verification.crl;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.net.URI;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Extracts CRL Distribution Point (CDP) HTTP(S) URIs from an Identity Certificate chain.
 *
 * <p>Resolution order: client leaf certificate first, then issuing CA in the presented chain.</p>
 */
public final class CdpExtractor {

    private static final Logger LOGGER = LoggerFactory.getLogger(CdpExtractor.class);

    private CdpExtractor() {
    }

    /**
     * Result of CDP discovery on a certificate chain.
     */
    public record CdpLookupResult(
            Status status,
            URI cdpUri,
            String failureMessage) {

        public enum Status {
            /** No CDP extension on the chain; CRL check should be skipped. */
            SKIPPED,
            /** A usable HTTP(S) CDP URI was found. */
            FOUND,
            /** CDP extension is present but unusable; CRL check should fail-closed. */
            FAILED
        }

        public static CdpLookupResult skipped() {
            return new CdpLookupResult(Status.SKIPPED, null, null);
        }

        public static CdpLookupResult found(URI uri) {
            return new CdpLookupResult(Status.FOUND, Objects.requireNonNull(uri, "uri"), null);
        }

        public static CdpLookupResult failed(String message) {
            return new CdpLookupResult(Status.FAILED, null, Objects.requireNonNull(message, "message"));
        }

        public boolean isSkipped() {
            return status == Status.SKIPPED;
        }

        public boolean isFound() {
            return status == Status.FOUND;
        }

        public boolean isFailed() {
            return status == Status.FAILED;
        }
    }

    /**
     * Resolves the first usable CDP URI from the certificate chain.
     *
     * @param chain presented certificate chain (index 0 = client leaf)
     * @return CDP lookup outcome
     */
    public static CdpLookupResult resolveFirstCdpUri(X509Certificate[] chain) {
        Objects.requireNonNull(chain, "chain");
        if (chain.length == 0) {
            return CdpLookupResult.skipped();
        }

        CdpUriExtraction leafExtraction = extractCdpUris(chain[0]);
        if (leafExtraction.failed()) {
            return CdpLookupResult.failed(leafExtraction.failureMessage());
        }
        if (leafExtraction.hasUri()) {
            return CdpLookupResult.found(leafExtraction.firstUri());
        }

        Optional<X509Certificate> issuer = findIssuingCa(chain[0], chain);
        if (issuer.isPresent() && issuer.get() != chain[0]) {
            CdpUriExtraction issuerExtraction = extractCdpUris(issuer.get());
            if (issuerExtraction.failed()) {
                return CdpLookupResult.failed(issuerExtraction.failureMessage());
            }
            if (issuerExtraction.hasUri()) {
                return CdpLookupResult.found(issuerExtraction.firstUri());
            }
        }

        LOGGER.debug("No CDP found on Identity Certificate chain; skipping CRL check");
        return CdpLookupResult.skipped();
    }

    /**
     * Extracts all HTTP(S) URIs from the CRL Distribution Points extension.
     */
    static CdpUriExtraction extractCdpUris(X509Certificate certificate) {
        Objects.requireNonNull(certificate, "certificate");
        byte[] extensionValue = certificate.getExtensionValue(Extension.cRLDistributionPoints.getId());
        if (extensionValue == null) {
            return CdpUriExtraction.absent();
        }

        try {
            CRLDistPoint distPoints = parseCrlDistPoint(extensionValue);
            List<URI> uris = new ArrayList<>();
            for (DistributionPoint dp : distPoints.getDistributionPoints()) {
                uris.addAll(extractUrisFromDistributionPoint(dp));
            }
            if (uris.isEmpty()) {
                return CdpUriExtraction.failed("CDP extension contains no HTTP(S) URI");
            }
            return CdpUriExtraction.found(Collections.unmodifiableList(uris));
        } catch (Exception e) {
            LOGGER.debug("Failed to parse CDP extension on {}: {}",
                certificate.getSubjectX500Principal(), e.getMessage());
            return CdpUriExtraction.failed("Failed to parse CDP extension: " + e.getMessage());
        }
    }

    static Optional<X509Certificate> findIssuingCa(X509Certificate leaf, X509Certificate[] chain) {
        for (int i = 1; i < chain.length; i++) {
            if (leaf.getIssuerX500Principal().equals(chain[i].getSubjectX500Principal())) {
                return Optional.of(chain[i]);
            }
        }
        return Optional.empty();
    }

    private static CRLDistPoint parseCrlDistPoint(byte[] extensionValue) throws Exception {
        try (ASN1InputStream asn1 = new ASN1InputStream(extensionValue)) {
            ASN1OctetString octets = (ASN1OctetString) asn1.readObject();
            return CRLDistPoint.getInstance(octets.getOctets());
        }
    }

    private static List<URI> extractUrisFromDistributionPoint(DistributionPoint dp) {
        DistributionPointName dpName = dp.getDistributionPoint();
        if (dpName == null || dpName.getType() != DistributionPointName.FULL_NAME) {
            return List.of();
        }

        GeneralNames names = GeneralNames.getInstance(dpName.getName());
        List<URI> uris = new ArrayList<>();
        for (GeneralName name : names.getNames()) {
            if (name.getTagNo() != GeneralName.uniformResourceIdentifier) {
                continue;
            }
            String uriString = name.getName().toString();
            if (uriString.startsWith("http://") || uriString.startsWith("https://")) {
                uris.add(URI.create(uriString));
            }
        }
        return uris;
    }

    record CdpUriExtraction(boolean extensionPresent, List<URI> uris, String failureMessage) {

        static CdpUriExtraction absent() {
            return new CdpUriExtraction(false, List.of(), null);
        }

        static CdpUriExtraction found(List<URI> uris) {
            return new CdpUriExtraction(true, uris, null);
        }

        static CdpUriExtraction failed(String message) {
            return new CdpUriExtraction(true, List.of(), message);
        }

        boolean failed() {
            return failureMessage != null;
        }

        boolean hasUri() {
            return !uris.isEmpty();
        }

        URI firstUri() {
            return uris.get(0);
        }
    }
}
