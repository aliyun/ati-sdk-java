package com.aliyun.ati.sdk.crypto;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HexFormat;
import java.util.List;
import java.util.Objects;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Utility class for working with X.509 certificates.
 *
 * <p>This class provides methods for parsing, validating, and converting
 * certificates between different formats.</p>
 *
 * <p>This is a lightweight implementation that uses only JDK classes (no BouncyCastle
 * dependency in core). For advanced PEM parsing with BouncyCastle, use the crypto
 * module's extended utilities.</p>
 */
public final class CertificateUtils {

    private static final Pattern PEM_CERT_PATTERN = Pattern.compile(
        "-----BEGIN CERTIFICATE-----\\s*([A-Za-z0-9+/\\s=]+)\\s*-----END CERTIFICATE-----",
        Pattern.DOTALL);

    private static final Pattern CN_PATTERN = Pattern.compile(
        "(?:^|,\\s*)CN\\s*=\\s*([^,]+)", Pattern.CASE_INSENSITIVE);

    private CertificateUtils() {
        // Utility class
    }

    /**
     * Parses a PEM-encoded certificate.
     *
     * @param pemCertificate the PEM-encoded certificate string
     * @return the parsed X509Certificate
     * @throws RuntimeException if parsing fails
     */
    public static X509Certificate parseCertificate(String pemCertificate) {
        if (pemCertificate == null || pemCertificate.isBlank()) {
            throw new IllegalArgumentException("PEM certificate cannot be null or blank");
        }

        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            byte[] derBytes = pemToDer(pemCertificate);
            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(derBytes));
        } catch (CertificateException e) {
            throw new RuntimeException("Failed to parse certificate", e);
        }
    }

    /**
     * Parses a PEM-encoded certificate chain.
     *
     * @param pemChain the PEM-encoded certificate chain string
     * @return list of parsed certificates, in the order they appear in the chain
     * @throws RuntimeException if parsing fails
     */
    public static List<X509Certificate> parseCertificateChain(String pemChain) {
        if (pemChain == null || pemChain.isBlank()) {
            throw new IllegalArgumentException("PEM chain cannot be null or blank");
        }

        List<X509Certificate> certificates = new ArrayList<>();
        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            Matcher matcher = PEM_CERT_PATTERN.matcher(pemChain);
            while (matcher.find()) {
                String base64 = matcher.group(1).replaceAll("\\s+", "");
                byte[] derBytes = Base64.getDecoder().decode(base64);
                certificates.add((X509Certificate) cf.generateCertificate(
                    new ByteArrayInputStream(derBytes)));
            }
        } catch (CertificateException e) {
            throw new RuntimeException("Failed to parse certificate chain", e);
        }

        if (certificates.isEmpty()) {
            throw new RuntimeException("No certificates found in chain");
        }

        return certificates;
    }

    /**
     * Converts a certificate to PEM format.
     *
     * @param certificate the certificate to convert
     * @return the PEM-encoded certificate string
     * @throws RuntimeException if conversion fails
     */
    public static String toPem(X509Certificate certificate) {
        if (certificate == null) {
            throw new IllegalArgumentException("Certificate cannot be null");
        }

        try {
            String base64 = Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.UTF_8))
                .encodeToString(certificate.getEncoded());
            return "-----BEGIN CERTIFICATE-----\n" + base64 + "\n-----END CERTIFICATE-----\n";
        } catch (CertificateEncodingException e) {
            throw new RuntimeException("Failed to convert certificate to PEM", e);
        }
    }

    /**
     * Checks if a certificate is currently valid (not expired and not before valid period).
     *
     * @param certificate the certificate to check
     * @return true if the certificate is currently valid
     */
    public static boolean isValid(X509Certificate certificate) {
        if (certificate == null) {
            return false;
        }
        Date now = new Date();
        return now.after(certificate.getNotBefore()) && now.before(certificate.getNotAfter());
    }

    /**
     * Checks if a certificate will expire within the specified number of days.
     *
     * @param certificate the certificate to check
     * @param days the number of days
     * @return true if the certificate will expire within the specified days
     */
    public static boolean expiresWithinDays(X509Certificate certificate, int days) {
        if (certificate == null) {
            return true;
        }
        long daysInMillis = days * 24L * 60L * 60L * 1000L;
        Date futureDate = new Date(System.currentTimeMillis() + daysInMillis);
        return certificate.getNotAfter().before(futureDate);
    }

    /**
     * Gets the common name (CN) from a certificate's subject.
     *
     * @param certificate the certificate
     * @return the common name, or null if not found
     */
    public static String getCommonName(X509Certificate certificate) {
        if (certificate == null) {
            return null;
        }
        try {
            String dn = certificate.getSubjectX500Principal().getName();
            Matcher matcher = CN_PATTERN.matcher(dn);
            if (matcher.find()) {
                return matcher.group(1).trim();
            }
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Gets the serial number of a certificate as a string.
     *
     * @param certificate the certificate
     * @return the serial number in hexadecimal format
     */
    public static String getSerialNumber(X509Certificate certificate) {
        if (certificate == null) {
            return null;
        }
        return certificate.getSerialNumber().toString(16);
    }

    /**
     * Computes the SHA-256 fingerprint of a certificate.
     *
     * @param certificate the certificate
     * @return the fingerprint in format "SHA256:hex-encoded-hash"
     * @throws RuntimeException if fingerprint computation fails
     */
    public static String computeSha256Fingerprint(X509Certificate certificate) {
        if (certificate == null) {
            throw new IllegalArgumentException("Certificate cannot be null");
        }
        try {
            byte[] digest = CryptoCache.sha256(certificate.getEncoded());
            StringBuilder hex = new StringBuilder("SHA256:");
            for (byte b : digest) {
                hex.append(String.format("%02x", b));
            }
            return hex.toString();
        } catch (CertificateEncodingException e) {
            throw new RuntimeException("Failed to compute certificate fingerprint", e);
        }
    }

    /**
     * Compares two fingerprints for equality, handling format differences.
     *
     * <p>This method handles fingerprints with or without the "SHA256:" prefix
     * and is case-insensitive.</p>
     *
     * @param actual the actual fingerprint
     * @param expected the expected fingerprint
     * @return true if the fingerprints match
     */
    public static boolean fingerprintMatches(String actual, String expected) {
        if (actual == null || expected == null) {
            return false;
        }
        String normalizedActual = normalizeFingerprint(actual);
        String normalizedExpected = normalizeFingerprint(expected);
        return MessageDigest.isEqual(
            normalizedActual.getBytes(StandardCharsets.UTF_8),
            normalizedExpected.getBytes(StandardCharsets.UTF_8));
    }

    /**
     * Normalizes a certificate fingerprint for comparison.
     *
     * @param fingerprint the fingerprint to normalize
     * @return the normalized fingerprint
     * @throws IllegalArgumentException if fingerprint is null
     */
    public static String normalizeFingerprint(String fingerprint) {
        if (fingerprint == null) {
            throw new IllegalArgumentException("fingerprint cannot be null");
        }
        String normalized = fingerprint.toLowerCase().trim();
        if (normalized.startsWith("sha256:")) {
            normalized = normalized.substring(7);
        } else if (normalized.startsWith("sha-256:")) {
            normalized = normalized.substring(8);
        }
        return normalized.replace(":", "").replace(" ", "");
    }

    /**
     * Converts a byte array to a lowercase hexadecimal string.
     *
     * @param bytes the byte array to convert
     * @return the hex string (lowercase)
     * @throws NullPointerException if bytes is null
     */
    public static String bytesToHex(byte[] bytes) {
        Objects.requireNonNull(bytes, "bytes cannot be null");
        return HexFormat.of().formatHex(bytes);
    }

    /**
     * Converts a hexadecimal string to a byte array.
     *
     * @param hex the hex string (must have even length)
     * @return the byte array
     * @throws NullPointerException if hex is null
     * @throws IllegalArgumentException if hex has odd length or invalid characters
     */
    public static byte[] hexToBytes(String hex) {
        Objects.requireNonNull(hex, "hex cannot be null");
        if (hex.length() % 2 != 0) {
            throw new IllegalArgumentException("Hex string must have even length");
        }
        return HexFormat.of().parseHex(hex);
    }

    /**
     * Truncates a fingerprint string for display in log messages.
     *
     * @param fingerprint the fingerprint to truncate (may be null)
     * @return the truncated fingerprint, or null if input is null
     */
    public static String truncateFingerprint(String fingerprint) {
        if (fingerprint == null || fingerprint.length() <= 16) {
            return fingerprint;
        }
        return fingerprint.substring(0, 16) + "...";
    }

    /**
     * Truncates a list of fingerprints for display in log messages.
     *
     * @param fingerprints the fingerprints to truncate
     * @return a truncated string representation
     */
    public static String truncateFingerprints(List<String> fingerprints) {
        if (fingerprints.size() <= 2) {
            return fingerprints.stream()
                .map(CertificateUtils::truncateFingerprint)
                .toList()
                .toString();
        }
        return "[" + truncateFingerprint(fingerprints.get(0))
            + ", ... (" + fingerprints.size() + " total)]";
    }

    /**
     * Extracts the FQDN from a certificate.
     *
     * <p>This method first checks DNS Subject Alternative Names, then falls back
     * to the Common Name (CN) if no DNS SAN is present.</p>
     *
     * @param certificate the certificate
     * @return the FQDN, or empty if not found
     */
    public static Optional<String> extractFqdn(X509Certificate certificate) {
        if (certificate == null) {
            return Optional.empty();
        }

        List<String> dnsNames = getDnsSubjectAltNames(certificate);
        if (!dnsNames.isEmpty()) {
            return Optional.of(dnsNames.get(0));
        }

        String cn = getCommonName(certificate);
        return Optional.ofNullable(cn);
    }

    /**
     * Extracts the ATI name from a certificate's URI Subject Alternative Name.
     *
     * <p>ATI names are stored in URI SANs and start with "ati://".</p>
     *
     * @param certificate the certificate
     * @return the ATI name, or empty if not found
     */
    public static Optional<String> extractAtiName(X509Certificate certificate) {
        if (certificate == null) {
            return Optional.empty();
        }

        List<String> uris = getUriSubjectAltNames(certificate);
        for (String uri : uris) {
            if (uri != null && uri.toLowerCase().startsWith("ati://")) {
                return Optional.of(uri);
            }
        }
        // Also check for legacy ANS name format
        for (String uri : uris) {
            if (uri != null && uri.toLowerCase().startsWith("ans://")) {
                return Optional.of(uri);
            }
        }
        return Optional.empty();
    }

    /**
     * Gets DNS Subject Alternative Names from a certificate.
     *
     * @param certificate the certificate
     * @return list of DNS names, empty if none
     */
    public static List<String> getDnsSubjectAltNames(X509Certificate certificate) {
        return getSubjectAltNames(certificate, 2);
    }

    /**
     * Pattern to extract host from ATI name URI SAN.
     * Matches: ati://v{version}.{host} or ati://{host} (also ans://)
     * Example: ati://v1.client-agent.example.com -> client-agent.example.com
     */
    private static final Pattern ATI_NAME_HOST_PATTERN = Pattern.compile(
        "^(?:ati|ans)://(?:v[^.]+\\.)?(.+)$",
        Pattern.CASE_INSENSITIVE
    );

    /**
     * Extracts the host portion from an ATI name URI.
     *
     * <p>Examples:</p>
     * <ul>
     *   <li>{@code ati://v1.client-agent.example.com} -> {@code client-agent.example.com}</li>
     *   <li>{@code ati://v1.0.0.client-agent.example.com} -> {@code client-agent.example.com}</li>
     *   <li>{@code ans://v1.client-agent.example.com} -> {@code client-agent.example.com}</li>
     * </ul>
     *
     * @param atiName the ATI name URI
     * @return the host portion, or null if parsing fails
     */
    public static String extractHostFromAtiName(String atiName) {
        if (atiName == null) {
            return null;
        }
        Matcher matcher = ATI_NAME_HOST_PATTERN.matcher(atiName);
        if (matcher.matches()) {
            return matcher.group(1);
        }
        return null;
    }

    /**
     * Gets URI Subject Alternative Names from a certificate.
     *
     * @param certificate the certificate
     * @return list of URIs, empty if none
     */
    public static List<String> getUriSubjectAltNames(X509Certificate certificate) {
        return getSubjectAltNames(certificate, 6);
    }

    /**
     * Gets Subject Alternative Names of a specific type.
     *
     * @param certificate the certificate
     * @param type the SAN type (2=DNS, 6=URI, etc.)
     * @return list of SANs, empty if none
     */
    private static List<String> getSubjectAltNames(X509Certificate certificate, int type) {
        if (certificate == null) {
            return Collections.emptyList();
        }
        try {
            Collection<List<?>> sans = certificate.getSubjectAlternativeNames();
            if (sans == null) {
                return Collections.emptyList();
            }
            List<String> result = new ArrayList<>();
            for (List<?> san : sans) {
                if (san.size() >= 2 && Integer.valueOf(type).equals(san.get(0))) {
                    Object value = san.get(1);
                    if (value instanceof String) {
                        result.add((String) value);
                    }
                }
            }
            return result;
        } catch (Exception e) {
            return Collections.emptyList();
        }
    }

    /**
     * Converts PEM-encoded certificate data to DER bytes.
     */
    private static byte[] pemToDer(String pem) {
        Matcher matcher = PEM_CERT_PATTERN.matcher(pem);
        if (!matcher.find()) {
            throw new IllegalArgumentException("Invalid PEM format");
        }
        String base64 = matcher.group(1).replaceAll("\\s+", "");
        return Base64.getDecoder().decode(base64);
    }
}
