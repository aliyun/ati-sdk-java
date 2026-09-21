package com.aliyun.ati.sdk.transparency.verification;

import com.aliyun.ati.sdk.crypto.CertificateUtils;
import com.aliyun.ati.sdk.transparency.model.TransparencyLog;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.erdtman.jcs.JsonCanonicalizer;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Base64;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The <b>Seal Validation Time</b> behavior matrix for {@link SealVerifier} (ADR 0012): the leaf Seal
 * Certificate and its whole chain are validated as-of {@code min(payload.timestamp, now)} — the
 * entry's own signed sealing time — instead of verification-time "now."
 *
 * <p>A genuine historical entry whose leaf has since expired still verifies when its authenticated
 * sealing time falls inside the leaf window; a signature sealed after the leaf's {@code notAfter}
 * (or before its {@code notBefore}) fails closed; a future timestamp is clamped to now; and a
 * missing/unparseable timestamp falls back to now. Asserted at the primary seam
 * {@link SealVerifier#verify(TransparencyLog, SealTrustChain)}.</p>
 *
 * <p>Kept in its own file (rather than folded into {@code SealVerifierTest}) so each stays under the
 * 500-line checkstyle {@code FileLength} limit; it reuses the same BouncyCastle Root → Intermediate →
 * Leaf harness and JCS signing pattern as {@code SealVerifierTest}.</p>
 */
class SealVerifierValidationTimeTest {

    private static final ObjectMapper MAPPER = new ObjectMapper()
        .setSerializationInclusion(JsonInclude.Include.NON_NULL);

    /** CNNIC's timezone offset, matching the production {@code payload.timestamp} shape. */
    private static final ZoneOffset SEALING_ZONE = ZoneOffset.ofHours(8);

    /** The CNNIC ATI signing identity the Seal Certificate leaf Subject must carry. */
    private static final X500Name CNNIC_ATI_LEAF_SUBJECT =
        new X500Name("C=CN, O=中国互联网络信息中心, OU=ATI, CN=cnnic-ati-tl-service");

    private static final String AGENT_ID = "6bf2b7a9-1383-4e33-a945-845f34af7526";
    private static final String HOSTNAME = "agent.example.com";
    private static final String ATI_NAME = "ati://v1.0.0." + HOSTNAME;
    private static final String FINGERPRINT =
        "SHA-256:213879842f4216be15291a7dc0102d10379f7d94b1f39d16a240c3b6c72a34d0";

    // ==================== Behavior matrix (ADR 0012) ====================

    @Test
    @DisplayName("Leaf expired at now but sealed inside its window verifies (the fix)")
    void shouldVerifyExpiredLeafSealedInsideWindow() throws Exception {
        // The leaf rotated out (expired 30d ago) but CNNIC sealed the entry 60d ago, while it was
        // valid. asOf = min(60d ago, now) = 60d ago, inside [notBefore=90d, notAfter=30d].
        Leaf leaf = leafFromTestCa(CNNIC_ATI_LEAF_SUBJECT, daysAgo(90), daysAgo(30));
        TransparencyLog log = signedLog(leaf, sealingTimeAt(daysAgo(60)));

        SealVerifier.VerificationResult result = SealVerifier.verify(log, TEST_CHAIN);

        assertThat(result.isValid()).isTrue();
        assertThat(result.sealValid()).isTrue();
    }

    @Test
    @DisplayName("A signature sealed after the leaf's notAfter fails (post-expiry signature)")
    void shouldRejectSignatureSealedAfterLeafNotAfter() throws Exception {
        // The leaf expired 30d ago; the entry claims a sealing time 10d ago — after notAfter.
        // asOf = 10d ago is outside the leaf window, so the post-expiry signature fails closed.
        Leaf leaf = leafFromTestCa(CNNIC_ATI_LEAF_SUBJECT, daysAgo(90), daysAgo(30));
        TransparencyLog log = signedLog(leaf, sealingTimeAt(daysAgo(10)));

        SealVerifier.VerificationResult result = SealVerifier.verify(log, TEST_CHAIN);

        assertThat(result.isValid()).isFalse();
        assertThat(result.sealValid()).isFalse();
    }

    @Test
    @DisplayName("A timestamp before the leaf's notBefore fails (strict lower bound)")
    void shouldRejectTimestampBeforeLeafNotBefore() throws Exception {
        // The entry claims a sealing time 60d ago, before the leaf existed (notBefore=30d ago).
        // asOf = 60d ago is below the strict lower bound, so a backdated forgery fails closed.
        Leaf leaf = leafFromTestCa(CNNIC_ATI_LEAF_SUBJECT, daysAgo(30), daysAhead(30));
        TransparencyLog log = signedLog(leaf, sealingTimeAt(daysAgo(60)));

        SealVerifier.VerificationResult result = SealVerifier.verify(log, TEST_CHAIN);

        assertThat(result.isValid()).isFalse();
        assertThat(result.sealValid()).isFalse();
    }

    @Test
    @DisplayName("A future timestamp is clamped to now, so a not-yet-valid leaf still fails")
    void shouldClampFutureTimestampToNow() throws Exception {
        // The leaf is not yet valid (notBefore=1d ahead). A future sealing time (5d ahead) must be
        // clamped to now — otherwise it would launder the not-yet-valid leaf into passing.
        Leaf leaf = leafFromTestCa(CNNIC_ATI_LEAF_SUBJECT, daysAhead(1), daysAhead(30));
        TransparencyLog log = signedLog(leaf, sealingTimeAt(daysAhead(5)));

        SealVerifier.VerificationResult result = SealVerifier.verify(log, TEST_CHAIN);

        assertThat(result.isValid()).isFalse();
        assertThat(result.sealValid()).isFalse();
    }

    @Test
    @DisplayName("A missing timestamp falls back to now, so an expired leaf fails")
    void shouldFallBackToNowWhenTimestampMissing() throws Exception {
        // No authenticated sealing time → validate at now. The leaf expired 30d ago → fails closed.
        Leaf leaf = leafFromTestCa(CNNIC_ATI_LEAF_SUBJECT, daysAgo(90), daysAgo(30));
        TransparencyLog log = signedLog(leaf, null);
        assertThat(log.getPayload()).doesNotContainKey("timestamp");

        SealVerifier.VerificationResult result = SealVerifier.verify(log, TEST_CHAIN);

        assertThat(result.isValid()).isFalse();
        assertThat(result.sealValid()).isFalse();
    }

    @Test
    @DisplayName("An unparseable timestamp falls back to now, so an expired leaf fails")
    void shouldFallBackToNowWhenTimestampUnparseable() throws Exception {
        Leaf leaf = leafFromTestCa(CNNIC_ATI_LEAF_SUBJECT, daysAgo(90), daysAgo(30));
        TransparencyLog log = signedLog(leaf, "not-an-iso-8601-timestamp");

        SealVerifier.VerificationResult result = SealVerifier.verify(log, TEST_CHAIN);

        assertThat(result.isValid()).isFalse();
        assertThat(result.sealValid()).isFalse();
    }

    @Test
    @DisplayName("A blank timestamp falls back to now, so an expired leaf fails")
    void shouldFallBackToNowWhenTimestampBlank() throws Exception {
        // A present-but-blank timestamp is treated exactly like a missing one (the isBlank guard):
        // fall back to now, where the 30d-expired leaf fails closed.
        Leaf leaf = leafFromTestCa(CNNIC_ATI_LEAF_SUBJECT, daysAgo(90), daysAgo(30));
        TransparencyLog log = signedLog(leaf, "   ");

        SealVerifier.VerificationResult result = SealVerifier.verify(log, TEST_CHAIN);

        assertThat(result.isValid()).isFalse();
        assertThat(result.sealValid()).isFalse();
    }

    @Test
    @DisplayName("A missing timestamp with a leaf valid at now verifies (fallback to now)")
    void shouldVerifyWhenTimestampMissingAndLeafValidAtNow() throws Exception {
        Leaf leaf = leafFromTestCa(CNNIC_ATI_LEAF_SUBJECT, daysAgo(1), daysAhead(365));
        TransparencyLog log = signedLog(leaf, null);
        assertThat(log.getPayload()).doesNotContainKey("timestamp");

        SealVerifier.VerificationResult result = SealVerifier.verify(log, TEST_CHAIN);

        assertThat(result.isValid()).isTrue();
        assertThat(result.sealValid()).isTrue();
    }

    @Test
    @DisplayName("An unparseable timestamp with a leaf valid at now verifies (fallback to now)")
    void shouldVerifyWhenTimestampUnparseableAndLeafValidAtNow() throws Exception {
        // Completes the matrix: an unparseable timestamp falls back to now, where a currently-valid
        // leaf verifies — the PASS counterpart to shouldFallBackToNowWhenTimestampUnparseable.
        Leaf leaf = leafFromTestCa(CNNIC_ATI_LEAF_SUBJECT, daysAgo(1), daysAhead(365));
        TransparencyLog log = signedLog(leaf, "not-an-iso-8601-timestamp");

        SealVerifier.VerificationResult result = SealVerifier.verify(log, TEST_CHAIN);

        assertThat(result.isValid()).isTrue();
        assertThat(result.sealValid()).isTrue();
    }

    @Test
    @DisplayName("The convenience verify(log) overload uses Seal Validation Time too (shared internal path)")
    void convenienceOverloadSharesAsOfPath() throws Exception {
        // verify(log) delegates to verify(log, shipped()). A test leaf never chains to the shipped
        // production anchor, so both an expired-but-in-window leaf and a currently-valid leaf fail —
        // and they fail IDENTICALLY, on the same trust-anchor reason. That equality proves the
        // expired leaf was validated as-of its sealing time (reaching the anchor check), not at
        // "now" (which would have tripped the earlier validity check with a different reason).
        Leaf expiredInWindow = leafFromTestCa(CNNIC_ATI_LEAF_SUBJECT, daysAgo(90), daysAgo(30));
        TransparencyLog expiredLog = signedLog(expiredInWindow, sealingTimeAt(daysAgo(60)));
        Leaf validNow = leafFromTestCa(CNNIC_ATI_LEAF_SUBJECT, daysAgo(1), daysAhead(365));
        TransparencyLog validLog = signedLog(validNow, sealingTimeAt(new Date()));

        SealVerifier.VerificationResult expiredResult = SealVerifier.verify(expiredLog);
        SealVerifier.VerificationResult validResult = SealVerifier.verify(validLog);

        assertThat(expiredResult.isValid()).isFalse();
        assertThat(validResult.isValid()).isFalse();
        assertThat(expiredResult.failureReason()).isEqualTo(validResult.failureReason());
    }

    // ==================== Signed TL builder ====================

    /**
     * Builds an ACTIVE cert-based TL whose seal carries {@code leaf.certificate} and a
     * SHA-256withRSA signature over the JCS content {status, schemaVersion, payload}. The signed
     * {@code payload.timestamp} (sealing time) is {@code payloadTimestamp}, chosen independently of
     * the leaf window; {@code null} omits it, modelling an entry with no authenticated sealing time.
     */
    private static TransparencyLog signedLog(Leaf leaf, String payloadTimestamp) throws Exception {
        Map<String, Object> certificates = new LinkedHashMap<>();
        certificates.put("serverCertFingerprint", FINGERPRINT);
        certificates.put("identityCertFingerprint", FINGERPRINT);

        Map<String, Object> payload = new LinkedHashMap<>();
        payload.put("logId", AGENT_ID);
        payload.put("eventType", "AGENT_REGISTERED");
        if (payloadTimestamp != null) {
            payload.put("timestamp", payloadTimestamp);
        }
        payload.put("agentName", ATI_NAME);
        payload.put("agentHost", HOSTNAME);
        payload.put("version", "1.0.0");
        payload.put("agentId", AGENT_ID);
        payload.put("agentStatus", "ACTIVE");
        payload.put("certificates", certificates);

        Map<String, Object> response = new LinkedHashMap<>();
        response.put("status", "ACTIVE");
        response.put("schemaVersion", "ATI-TL-V1");
        response.put("payload", payload);

        // SealVerifier signs {status, schemaVersion, payload} (evidenceRef is absent here), so the
        // test canonicalizes the same three keys — the chosen sealing time is covered by the seal.
        Map<String, Object> signedContent = new LinkedHashMap<>();
        signedContent.put("status", response.get("status"));
        signedContent.put("schemaVersion", response.get("schemaVersion"));
        signedContent.put("payload", response.get("payload"));
        byte[] canonicalBytes =
            new JsonCanonicalizer(MAPPER.writeValueAsString(signedContent)).getEncodedUTF8();

        Map<String, Object> seal = new LinkedHashMap<>();
        seal.put("canonicalization", "RFC8785-JCS");
        seal.put("digestAlgorithm", "SHA-256");
        seal.put("signatureAlgorithm", "SHA-256withRSA");
        seal.put("signatureEncoding", "DER_BASE64");
        seal.put("keyId", "ati-tl-rsa-v1");
        seal.put("signature", signRsa(leaf.keyPair(), canonicalBytes));
        seal.put("certificate", CertificateUtils.toPem(leaf.certificate()));
        response.put("seal", seal);

        return MAPPER.readValue(MAPPER.writeValueAsString(response), TransparencyLog.class);
    }

    private static String signRsa(KeyPair keyPair, byte[] canonicalBytes) throws Exception {
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(keyPair.getPrivate());
        signer.update(canonicalBytes);
        return Base64.getEncoder().encodeToString(signer.sign());
    }

    /** Formats {@code time} as ISO-8601 with CNNIC's {@code +08:00} offset (production shape). */
    private static String sealingTimeAt(Date time) {
        return DateTimeFormatter.ISO_OFFSET_DATE_TIME.format(time.toInstant().atOffset(SEALING_ZONE));
    }

    // ==================== Shared test CA chain (Root → Intermediate → Leaf) ====================

    private static final AtomicLong SERIAL = new AtomicLong(System.nanoTime());
    private static final X500Name ROOT_SUBJECT = new X500Name("C=CN, O=UniTrust, CN=Test Seal Root CA");
    private static final X500Name INTERMEDIATE_SUBJECT =
        new X500Name("C=CN, O=UniTrust, CN=Test Seal Intermediate CA");

    private static final KeyPair ROOT_KEY;
    private static final X509Certificate ROOT_CERT;
    private static final KeyPair INTERMEDIATE_KEY;
    private static final X509Certificate INTERMEDIATE_CERT;
    private static final SealTrustChain TEST_CHAIN;

    static {
        try {
            ROOT_KEY = generateRsaKeyPair();
            INTERMEDIATE_KEY = generateRsaKeyPair();
            // Long-lived CA (production Root →2043, Intermediate →2033): backdate notBefore so a
            // historical sealing time still chains under Seal Validation Time checks (ADR 0012).
            ROOT_CERT = buildCertificate(ROOT_SUBJECT, ROOT_KEY.getPublic(),
                ROOT_SUBJECT, ROOT_KEY.getPrivate(), daysAgo(3650), daysAhead(3650), true, null);
            INTERMEDIATE_CERT = buildCertificate(INTERMEDIATE_SUBJECT, INTERMEDIATE_KEY.getPublic(),
                ROOT_SUBJECT, ROOT_KEY.getPrivate(), daysAgo(3650), daysAhead(1825), true, 0);
            TEST_CHAIN = SealTrustChain.of(ROOT_CERT, INTERMEDIATE_CERT);
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    /** A generated leaf Seal Certificate plus the key pair that signs with it. */
    private record Leaf(KeyPair keyPair, X509Certificate certificate) {
    }

    private static Leaf leafFromTestCa(X500Name subject, Date notBefore, Date notAfter) throws Exception {
        KeyPair keyPair = generateRsaKeyPair();
        X509Certificate cert = buildCertificate(subject, keyPair.getPublic(),
            INTERMEDIATE_SUBJECT, INTERMEDIATE_KEY.getPrivate(), notBefore, notAfter, false, null);
        return new Leaf(keyPair, cert);
    }

    private static KeyPair generateRsaKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static X509Certificate buildCertificate(
            X500Name subject, PublicKey subjectKey,
            X500Name issuer, PrivateKey issuerKey,
            Date notBefore, Date notAfter, boolean ca, Integer pathLen) throws Exception {
        BigInteger serial = BigInteger.valueOf(SERIAL.incrementAndGet());
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
            issuer, serial, notBefore, notAfter, subject, subjectKey);
        if (ca) {
            BasicConstraints basicConstraints =
                pathLen == null ? new BasicConstraints(true) : new BasicConstraints(pathLen.intValue());
            builder.addExtension(Extension.basicConstraints, true, basicConstraints);
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        } else {
            builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(false));
            builder.addExtension(Extension.keyUsage, true, new KeyUsage(KeyUsage.digitalSignature));
        }
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(issuerKey);
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    private static Date daysAgo(long days) {
        return Date.from(Instant.now().minusSeconds(86400L * days));
    }

    private static Date daysAhead(long days) {
        return Date.from(Instant.now().plusSeconds(86400L * days));
    }
}
