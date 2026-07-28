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
     * Returns the first usable CDP URI from the certificate chain, or empty if none is present.
     *
     * @param chain presented certificate chain (index 0 = client leaf)
     * @return optional CDP URI
     */
    public static Optional<URI> extractFirstCdpUri(X509Certificate[] chain) {
        Objects.requireNonNull(chain, "chain");
        if (chain.length == 0) {
            return Optional.empty();
        }

        List<URI> leafUris = extractCdpUris(chain[0]);
        if (!leafUris.isEmpty()) {
            return Optional.of(leafUris.get(0));
        }

        X509Certificate issuer = findIssuingCa(chain[0], chain).orElse(null);
        if (issuer != null && issuer != chain[0]) {
            List<URI> issuerUris = extractCdpUris(issuer);
            if (!issuerUris.isEmpty()) {
                return Optional.of(issuerUris.get(0));
            }
        }

        LOGGER.debug("No CDP found on Identity Certificate chain; skipping CRL check");
        return Optional.empty();
    }

    /**
     * Extracts all HTTP(S) URIs from the CRL Distribution Points extension.
     */
    static List<URI> extractCdpUris(X509Certificate certificate) {
        Objects.requireNonNull(certificate, "certificate");
        byte[] extensionValue = certificate.getExtensionValue(Extension.cRLDistributionPoints.getId());
        if (extensionValue == null) {
            return List.of();
        }

        try {
            CRLDistPoint distPoints = parseCrlDistPoint(extensionValue);
            List<URI> uris = new ArrayList<>();
            for (DistributionPoint dp : distPoints.getDistributionPoints()) {
                uris.addAll(extractUrisFromDistributionPoint(dp));
            }
            return Collections.unmodifiableList(uris);
        } catch (Exception e) {
            LOGGER.debug("Failed to parse CDP extension on {}: {}",
                certificate.getSubjectX500Principal(), e.getMessage());
            return List.of();
        }
    }

    static Optional<X509Certificate> findIssuingCa(X509Certificate leaf, X509Certificate[] chain) {
        if (chain.length >= 2) {
            return Optional.of(chain[1]);
        }
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
}
