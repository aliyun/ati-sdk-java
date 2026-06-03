package com.aliyun.ati.sdk.agent.verification;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.time.Duration;
import java.util.Objects;

import com.aliyun.ati.sdk.crypto.CertUtils;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xbill.DNS.Lookup;
import org.xbill.DNS.Record;
import org.xbill.DNS.SimpleResolver;
import org.xbill.DNS.TLSARecord;
import org.xbill.DNS.Type;

public final class DaneTlsaVerifier {

    private static final Logger LOG =
        LoggerFactory.getLogger(DaneTlsaVerifier.class);
    private static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(5);
    private static final int USAGE_DANE_EE = 3;
    private static final int SELECTOR_SPKI = 1;
    private static final int MATCHING_SHA256 = 1;

    private final Duration timeout;

    public DaneTlsaVerifier() {
        this(DEFAULT_TIMEOUT);
    }

    public DaneTlsaVerifier(Duration timeout) {
        this.timeout = Objects.requireNonNull(timeout,
            "timeout must not be null");
    }

    public VerificationResult verify(String host, int port,
                                     X509Certificate serverCert) {
        Objects.requireNonNull(host, "host must not be null");
        Objects.requireNonNull(serverCert, "serverCert must not be null");

        String tlsaName = "_" + port + "._tcp." + host;
        LOG.debug("Looking up TLSA record: {}", tlsaName);

        try {
            Lookup lookup = new Lookup(tlsaName, Type.TLSA);
            SimpleResolver resolver = new SimpleResolver();
            resolver.setTimeout(timeout);
            lookup.setResolver(resolver);
            Record[] records = lookup.run();

            if (records == null || records.length == 0) {
                LOG.debug("No TLSA record found for {}", tlsaName);
                return VerificationResult.failure(
                    VerificationResult.Type.DANE,
                    VerificationResult.Status.NOT_FOUND,
                    "No TLSA record for " + tlsaName);
            }

            for (Record record : records) {
                if (!(record instanceof TLSARecord)) {
                    continue;
                }

                TLSARecord tlsa = (TLSARecord) record;

                if (tlsa.getCertificateUsage() == USAGE_DANE_EE
                    && tlsa.getSelector() == SELECTOR_SPKI
                    && tlsa.getMatchingType() == MATCHING_SHA256) {

                    byte[] spki =
                        serverCert.getPublicKey().getEncoded();
                    String actualHash = CertUtils.sha256Hex(spki);
                    String expectedHash =
                        bytesToHex(tlsa.getCertificateAssociationData());

                    if (MessageDigest.isEqual(
                            actualHash.getBytes(StandardCharsets.UTF_8),
                            expectedHash.getBytes(StandardCharsets.UTF_8))) {
                        LOG.debug(
                            "DANE TLSA verification succeeded for {}",
                            host);
                        return VerificationResult.success(
                            VerificationResult.Type.DANE);
                    } else {
                        LOG.warn(
                            "DANE TLSA fingerprint mismatch for {}",
                            host);
                        return VerificationResult.failure(
                            VerificationResult.Type.DANE,
                            VerificationResult.Status.MISMATCH,
                            "TLSA fingerprint mismatch for " + host);
                    }
                }
            }

            return VerificationResult.failure(
                VerificationResult.Type.DANE,
                VerificationResult.Status.NOT_FOUND,
                "No matching TLSA record type for " + tlsaName);

        } catch (Exception e) {
            LOG.error("DANE TLSA lookup failed for {}", tlsaName, e);
            return VerificationResult.failure(
                VerificationResult.Type.DANE,
                VerificationResult.Status.ERROR,
                "DNS lookup error: " + e.getMessage());
        }
    }

    private static String bytesToHex(byte[] bytes) {
        char[] hex = "0123456789abcdef".toCharArray();
        char[] result = new char[bytes.length * 2];
        for (int i = 0; i < bytes.length; i++) {
            result[i * 2] = hex[(bytes[i] >> 4) & 0x0F];
            result[i * 2 + 1] = hex[bytes[i] & 0x0F];
        }
        return new String(result);
    }
}
