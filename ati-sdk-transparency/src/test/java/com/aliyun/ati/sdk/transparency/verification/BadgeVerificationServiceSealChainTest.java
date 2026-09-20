package com.aliyun.ati.sdk.transparency.verification;

import com.aliyun.ati.sdk.crypto.CertificateUtils;
import com.aliyun.ati.sdk.transparency.TransparencyClient;
import com.aliyun.ati.sdk.transparency.dns.RaBadgeLookupService;
import com.aliyun.ati.sdk.transparency.dns.RaBadgeRecord;
import com.aliyun.ati.sdk.transparency.model.TransparencyLog;
import com.aliyun.ati.sdk.transparency.model.TransparencyLogAtiV1;
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
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Integration tests at the {@link BadgeVerificationService} seam proving the Seal CA Chain flows
 * through Badge pre-verification (ADR 0011, spec Integration decision).
 *
 * <p>A cert-based Seal signed by the injected chain's leaf verifies and yields
 * {@link VerificationStatus#VERIFIED}; the injected chain is provably the one used, because the
 * locally generated leaf does not chain to the SDK-shipped production anchor. A certificate-less
 * (legacy {@code publicKey}-only) Seal or a tampered entry fails closed with
 * {@link VerificationStatus#SEAL_VERIFICATION_FAILED}.</p>
 */
class BadgeVerificationServiceSealChainTest {

    private static final String HOSTNAME = "agent.example.com";
    private static final String AGENT_ID = "6bf2b7a9-1383-4e33-a945-845f34af7526";
    private static final String TL_PATH = "/tl/agents/" + AGENT_ID;
    private static final String BADGE_TXT =
        "v=ati-badge1; av=1.0.0; u=https://ati-tl.cnnic.cn:8180" + TL_PATH;
    private static final String FINGERPRINT =
        "SHA-256:213879842f4216be15291a7dc0102d10379f7d94b1f39d16a240c3b6c72a34d0";
    private static final String ATI_NAME = "ati://v1.0.0." + HOSTNAME;

    private static final ObjectMapper MAPPER = new ObjectMapper()
        .setSerializationInclusion(JsonInclude.Include.NON_NULL);

    /** CNNIC's timezone offset, matching the production {@code payload.timestamp} shape. */
    private static final ZoneOffset SEALING_ZONE = ZoneOffset.ofHours(8);

    /** The CNNIC ATI signing identity the Seal Certificate leaf Subject must carry. */
    private static final X500Name CNNIC_ATI_LEAF_SUBJECT =
        new X500Name("C=CN, O=中国互联网络信息中心, OU=ATI, CN=cnnic-ati-tl-service");

    @Test
    @DisplayName("A cert-based Seal signed by the injected chain verifies → VERIFIED")
    void certBasedSealPassesPreVerification() throws Exception {
        Leaf leaf = leafFromTestCa(CNNIC_ATI_LEAF_SUBJECT, daysAgo(1), daysAhead(365));
        TransparencyLog registration = signedRegistration(leaf, true);

        BadgeVerificationService service = serviceReturning(registration, TEST_CHAIN);

        ServerVerificationResult result = service.verifyServer(HOSTNAME);

        assertThat(result.getStatus()).isEqualTo(VerificationStatus.VERIFIED);
        assertThat(result.isSealVerified()).isTrue();
        assertThat(result.getExpectedServerCertFingerprint()).isEqualTo(FINGERPRINT);
        assertThat(result.getExpectedAgentHost()).isEqualTo(HOSTNAME);
    }

    @Test
    @DisplayName("A chosen sealing time inside the leaf window verifies → VERIFIED (harness parameterization)")
    void chosenSealingTimeInsideLeafWindowVerifies() throws Exception {
        // Chosen sealing time inside the leaf window: proves the timestamp is injected into the
        // JCS-signed content, staying green under validity-at-now and ticket 02's as-of rule.
        Leaf leaf = leafFromTestCa(CNNIC_ATI_LEAF_SUBJECT, daysAgo(10), daysAhead(10));
        String sealingTime = sealingTimeAt(daysAgo(5));
        TransparencyLog registration = signedRegistration(leaf, true, sealingTime);

        BadgeVerificationService service = serviceReturning(registration, TEST_CHAIN);

        ServerVerificationResult result = service.verifyServer(HOSTNAME);

        assertThat(result.getStatus()).isEqualTo(VerificationStatus.VERIFIED);
        assertThat(result.isSealVerified()).isTrue();
        assertThat(registration.getPayload()).containsEntry("timestamp", sealingTime);
    }

    @Test
    @DisplayName("A certificate-less (publicKey-only) Seal fails closed → SEAL_VERIFICATION_FAILED")
    void certificateLessSealFailsClosed() throws Exception {
        Leaf leaf = leafFromTestCa(CNNIC_ATI_LEAF_SUBJECT, daysAgo(1), daysAhead(365));
        TransparencyLog registration = signedRegistration(leaf, false);
        assertThat(registration.getSeal().getCertificate()).isNull();

        BadgeVerificationService service = serviceReturning(registration, TEST_CHAIN);

        ServerVerificationResult result = service.verifyServer(HOSTNAME);

        assertThat(result.getStatus()).isEqualTo(VerificationStatus.SEAL_VERIFICATION_FAILED);
        assertThat(result.isSuccess()).isFalse();
        assertThat(result.getFailureStep()).isEqualTo("seal");
    }

    @Test
    @DisplayName("A tampered Badge Entry fails closed → SEAL_VERIFICATION_FAILED")
    void tamperedEntryFailsClosed() throws Exception {
        Leaf leaf = leafFromTestCa(CNNIC_ATI_LEAF_SUBJECT, daysAgo(1), daysAhead(365));
        TransparencyLog registration = signedRegistration(leaf, true);
        registration.setStatus("REVOKED"); // breaks the seal signature over the JCS content

        BadgeVerificationService service = serviceReturning(registration, TEST_CHAIN);

        ServerVerificationResult result = service.verifyServer(HOSTNAME);

        assertThat(result.getStatus()).isEqualTo(VerificationStatus.SEAL_VERIFICATION_FAILED);
        assertThat(result.isSuccess()).isFalse();
    }

    /**
     * Builds a service whose single Badge resolves to {@code registration}, anchored on
     * {@code sealTrustChain} (proving the injected chain — not the shipped one — is used).
     */
    private BadgeVerificationService serviceReturning(
            TransparencyLog registration, SealTrustChain sealTrustChain) {
        RaBadgeLookupService lookup = mock(RaBadgeLookupService.class);
        when(lookup.lookupBadges(HOSTNAME)).thenReturn(List.of(RaBadgeRecord.parse(BADGE_TXT)));

        TransparencyClient client = mock(TransparencyClient.class);
        when(client.getTransparencyLogByPath(TL_PATH)).thenReturn(registration);

        return BadgeVerificationService.builder()
            .transparencyClient(client)
            .raBadgeLookupService(lookup)
            .sealTrustChain(sealTrustChain)
            .build();
    }

    // ==================== Signed registration builder ====================

    /**
     * Builds an ACTIVE registration whose Seal carries a SHA-256withRSA signature over the JCS
     * content {status, schemaVersion, payload}. When {@code withCertificate} the seal carries the
     * leaf certificate (chains to {@link #TEST_CHAIN}); otherwise it is a legacy publicKey-only
     * seal with no {@code seal.certificate}, which must fail closed after the contract. The sealing
     * time defaults to "now", which sits inside the happy-path leaf window ({@code daysAgo(1)} to
     * {@code daysAhead(365)}).
     */
    private static TransparencyLog signedRegistration(Leaf leaf, boolean withCertificate) throws Exception {
        return signedRegistration(leaf, withCertificate, sealingTimeAt(new Date()));
    }

    /**
     * Builds an ACTIVE registration whose signed {@code payload.timestamp} (the sealing time) is
     * {@code payloadTimestamp}, chosen independently of the leaf's validity window. A {@code null}
     * timestamp omits the field, modelling an entry with no authenticated sealing time.
     */
    private static TransparencyLog signedRegistration(
            Leaf leaf, boolean withCertificate, String payloadTimestamp) throws Exception {
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
        if (withCertificate) {
            seal.put("certificate", CertificateUtils.toPem(leaf.certificate()));
        } else {
            seal.put("publicKey", toPublicKeyPem(leaf.keyPair()));
        }
        response.put("seal", seal);

        TransparencyLog log =
            MAPPER.readValue(MAPPER.writeValueAsString(response), TransparencyLog.class);
        log.setParsedPayload(parsedPayload(payloadTimestamp));
        return log;
    }

    private static TransparencyLogAtiV1 parsedPayload(String timestamp) {
        TransparencyLogAtiV1 payload = new TransparencyLogAtiV1();
        payload.setTimestamp(timestamp);
        payload.setAgentName(ATI_NAME);
        payload.setAgentHost(HOSTNAME);
        payload.setVersion("1.0.0");
        payload.setAgentId(AGENT_ID);
        payload.setAgentStatus("ACTIVE");

        TransparencyLogAtiV1.Certificates certs = new TransparencyLogAtiV1.Certificates();
        certs.setServerCertFingerprint(FINGERPRINT);
        certs.setIdentityCertFingerprint(FINGERPRINT);
        payload.setCertificates(certs);
        return payload;
    }

    // ==================== Test CA chain (Root → Intermediate → Leaf) ====================

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
            ROOT_CERT = buildCertificate(ROOT_SUBJECT, ROOT_KEY.getPublic(),
                ROOT_SUBJECT, ROOT_KEY.getPrivate(), daysAgo(1), daysAhead(3650), true, null);
            INTERMEDIATE_CERT = buildCertificate(INTERMEDIATE_SUBJECT, INTERMEDIATE_KEY.getPublic(),
                ROOT_SUBJECT, ROOT_KEY.getPrivate(), daysAgo(1), daysAhead(1825), true, 0);
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

    private static String signRsa(KeyPair keyPair, byte[] canonicalBytes) throws Exception {
        Signature signer = Signature.getInstance("SHA256withRSA");
        signer.initSign(keyPair.getPrivate());
        signer.update(canonicalBytes);
        return Base64.getEncoder().encodeToString(signer.sign());
    }

    private static String toPublicKeyPem(KeyPair keyPair) {
        String body = Base64.getMimeEncoder(64, new byte[]{'\n'})
            .encodeToString(keyPair.getPublic().getEncoded());
        return "-----BEGIN PUBLIC KEY-----\n" + body + "\n-----END PUBLIC KEY-----";
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

    /**
     * Formats {@code time} as an ISO-8601 timestamp with CNNIC's {@code +08:00} offset, matching the
     * production {@code payload.timestamp} shape the Seal Validation Time parser (ticket 02) reads.
     */
    private static String sealingTimeAt(Date time) {
        return DateTimeFormatter.ISO_OFFSET_DATE_TIME.format(time.toInstant().atOffset(SEALING_ZONE));
    }
}
