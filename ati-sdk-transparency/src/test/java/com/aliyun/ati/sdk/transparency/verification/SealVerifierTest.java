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
import org.junit.jupiter.api.Nested;
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
 * Tests for {@link SealVerifier}.
 *
 * <p>Covers the certificate-based verification path — the only path after the Seal CA Chain
 * contract:</p>
 * <ul>
 *   <li><b>Certificate path</b> — {@link SealVerifier#verify(TransparencyLog, SealTrustChain)}
 *       verifies with the public key inside {@code seal.certificate}, PKIX path-validates that leaf
 *       to an injected {@link SealTrustChain} as-of the entry's sealing time (ADR 0012), and binds
 *       the leaf Subject to {@code O=中国互联网络信息中心} (CNNIC) + {@code OU=ATI} (ADR 0011).</li>
 *   <li><b>Convenience overload</b> — {@link SealVerifier#verify(TransparencyLog)} delegates to the
 *       shipped Seal CA Chain, so a Seal without {@code seal.certificate} fails closed.</li>
 * </ul>
 *
 * <p>The certificate path is exercised against a locally generated BouncyCastle
 * Root → Intermediate → Leaf chain, since the real UniTrust leaf private key is unavailable.</p>
 */
class SealVerifierTest {

    private static final ObjectMapper MAPPER = new ObjectMapper()
        .setSerializationInclusion(JsonInclude.Include.NON_NULL);

    /** CNNIC's timezone offset, matching the production {@code payload.timestamp} shape. */
    private static final ZoneOffset SEALING_ZONE = ZoneOffset.ofHours(8);

    /** The CNNIC ATI signing identity the Seal Certificate leaf Subject must carry. */
    private static final X500Name CNNIC_ATI_LEAF_SUBJECT =
        new X500Name("C=CN, O=中国互联网络信息中心, OU=ATI, CN=cnnic-ati-tl-service");

    /**
     * Production-shaped TL body (seal replaced with a locally signed value).
     * evidenceRef includes signature metadata that EvidenceRef does not model.
     *
     * <p>The payload carries no {@code timestamp}: the signing helpers inject the sealing time (see
     * {@link #applySealingTime}), replacing the old hardcoded {@code 2026-05-18} value.</p>
     */
    private static final String TL_BODY = """
        {
          "status": "ACTIVE",
          "schemaVersion": "ATI-TL-V1",
          "payload": {
            "logId": "28b8f491-f110-4705-b8b9-dc8e91d452e0",
            "eventType": "AGENT_REGISTERED",
            "agentName": "ati://v1.demo.example.com",
            "agentDisplayName": "demo-agent",
            "agentHost": "demo.example.com",
            "version": "1.0.0",
            "agentId": "agent-001",
            "agentStatus": "ACTIVE",
            "certificates": {
              "serverCertFingerprint": "SHA-256:server-cert-fingerprint",
              "identityCertFingerprint": "SHA-256:identity-cert-fingerprint"
            }
          },
          "evidenceRef": {
            "evidenceId": "aliyun-evidence-agent-001",
            "submitterId": "aliyun",
            "evidenceType": "ALIYUN_SIGNED_SUBMISSION",
            "evidenceUri": "https://example.aliyun.com/ati/evidence/agent-001.json",
            "evidenceHash": "SHA-256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
            "hashAlgorithm": "SHA-256",
            "hashTarget": "EVIDENCE_BYTES",
            "contentType": "application/json",
            "evidenceSchemaVersion": "ATI-EVIDENCE-V1",
            "signatureRequired": true,
            "signatureAlgorithm": "SHA-256withECDSA",
            "signatureEncoding": "DER_BASE64",
            "signatureCanonicalization": "RFC8785-JCS",
            "signedContentLocation": "signedContent",
            "signatureLocation": "signature",
            "keyId": "aliyun-ati-v1"
          }
        }
        """;

    // ==================== Convenience overload — verify(log) delegates to shipped() ====================

    @Nested
    @DisplayName("Convenience verify(log) — delegates to the shipped Seal CA Chain")
    class ConvenienceOverload {

        @Test
        @DisplayName("A publicKey-only Seal (no seal.certificate) fails closed via verify(log)")
        void shouldRejectPublicKeyOnlySeal() throws Exception {
            // The legacy self-asserted publicKey path is gone: verify(log) now anchors on the
            // shipped Seal CA Chain, so a Seal with no certificate cannot verify.
            TransparencyLog log = signedLog("SHA-256withRSA");
            assertThat(log.getSeal().getCertificate()).isNull();

            SealVerifier.VerificationResult result = SealVerifier.verify(log);

            assertThat(result.isValid()).isFalse();
            assertThat(result.sealValid()).isFalse();
            assertThat(result.failureReason()).contains("certificate");
        }
    }

    // ==================== Certificate path — verify(log, trustChain) ====================

    @Nested
    @DisplayName("Certificate path — verify(log, trustChain)")
    class CertificatePath {

        @Test
        @DisplayName("Cert-based Seal verifies with the leaf certificate's public key")
        void shouldVerifyCertBasedSeal() throws Exception {
            Leaf leaf = leafFromTestCa(CNNIC_ATI_LEAF_SUBJECT, daysAgo(1), daysAhead(365));
            TransparencyLog log = certSignedLog(leaf, "SHA-256withRSA");

            SealVerifier.VerificationResult result = SealVerifier.verify(log, TEST_CHAIN);

            assertThat(result.isValid()).isTrue();
            assertThat(result.sealValid()).isTrue();
            // The signature only verifies because JCS canonicalization keeps the raw evidenceRef
            // extra keys that the typed EvidenceRef would drop (CHANGELOG 2.1.0 regression guard).
            assertThat(log.getRawEvidenceRef()).containsKeys(
                "signatureAlgorithm",
                "signatureEncoding",
                "signatureCanonicalization",
                "signedContentLocation",
                "signatureLocation",
                "keyId");
        }

        @Test
        @DisplayName("A chosen sealing time inside the leaf window verifies (harness parameterization)")
        void shouldVerifyWithChosenSealingTimeInsideLeafWindow() throws Exception {
            // Chosen sealing time inside the leaf window: proves the timestamp is injected into the
            // JCS-signed content, staying green under validity-at-now and ticket 02's as-of rule.
            Leaf leaf = leafFromTestCa(CNNIC_ATI_LEAF_SUBJECT, daysAgo(10), daysAhead(10));
            String sealingTime = sealingTimeAt(daysAgo(5));
            TransparencyLog log = certSignedLog(leaf, "SHA-256withRSA", sealingTime);

            SealVerifier.VerificationResult result = SealVerifier.verify(log, TEST_CHAIN);

            assertThat(result.isValid()).isTrue();
            assertThat(result.sealValid()).isTrue();
            assertThat(log.getPayload()).containsEntry("timestamp", sealingTime);
        }

        @Test
        @DisplayName("SealTrustChain.fromPem builds an equivalent chain from a Root + Intermediate PEM")
        void shouldVerifyWithChainBuiltFromPem() throws Exception {
            String pem = CertificateUtils.toPem(ROOT_CERT) + CertificateUtils.toPem(INTERMEDIATE_CERT);
            SealTrustChain fromPem = SealTrustChain.fromPem(pem);
            assertThat(fromPem.root().getEncoded()).isEqualTo(TEST_CHAIN.root().getEncoded());
            assertThat(fromPem.intermediate().getEncoded()).isEqualTo(TEST_CHAIN.intermediate().getEncoded());

            Leaf leaf = leafFromTestCa(CNNIC_ATI_LEAF_SUBJECT, daysAgo(1), daysAhead(365));
            TransparencyLog log = certSignedLog(leaf, "SHA-256withRSA");

            assertThat(SealVerifier.verify(log, fromPem).isValid()).isTrue();
        }

        @Test
        @DisplayName("Tampered Badge content fails on the certificate path")
        void shouldRejectTamperedContent() throws Exception {
            Leaf leaf = leafFromTestCa(CNNIC_ATI_LEAF_SUBJECT, daysAgo(1), daysAhead(365));
            TransparencyLog log = certSignedLog(leaf, "SHA-256withRSA");
            log.setStatus("REVOKED");

            SealVerifier.VerificationResult result = SealVerifier.verify(log, TEST_CHAIN);

            assertThat(result.isValid()).isFalse();
            assertThat(result.failureReason()).contains("Seal signature verification failed");
        }

        @Test
        @DisplayName("ECDSA signatureAlgorithm fails on the certificate path (allow-list)")
        void shouldRejectEcdsaAlgorithm() throws Exception {
            Leaf leaf = leafFromTestCa(CNNIC_ATI_LEAF_SUBJECT, daysAgo(1), daysAhead(365));
            TransparencyLog log = certSignedLog(leaf, "SHA-256withECDSA");

            SealVerifier.VerificationResult result = SealVerifier.verify(log, TEST_CHAIN);

            assertThat(result.isValid()).isFalse();
            assertThat(result.failureReason()).contains("SHA-256withRSA");
        }

        @Test
        @DisplayName("Missing signatureAlgorithm fails on the certificate path")
        void shouldRejectMissingAlgorithm() throws Exception {
            Leaf leaf = leafFromTestCa(CNNIC_ATI_LEAF_SUBJECT, daysAgo(1), daysAhead(365));
            TransparencyLog log = certSignedLog(leaf, null);

            SealVerifier.VerificationResult result = SealVerifier.verify(log, TEST_CHAIN);

            assertThat(result.isValid()).isFalse();
            assertThat(result.failureReason()).contains("signatureAlgorithm is required");
        }

        @Test
        @DisplayName("A publicKey-only Seal (no seal.certificate) fails closed on the certificate path")
        void shouldRejectSealWithoutCertificate() throws Exception {
            TransparencyLog log = signedLog("SHA-256withRSA");
            assertThat(log.getSeal().getCertificate()).isNull();

            SealVerifier.VerificationResult result = SealVerifier.verify(log, TEST_CHAIN);

            assertThat(result.isValid()).isFalse();
            assertThat(result.failureReason()).contains("certificate");
        }

        @Test
        @DisplayName("A leaf already expired at the sealing time (defaults to now) fails")
        void shouldRejectExpiredLeaf() throws Exception {
            Leaf leaf = leafFromTestCa(CNNIC_ATI_LEAF_SUBJECT, daysAgo(30), daysAgo(1));
            TransparencyLog log = certSignedLog(leaf, "SHA-256withRSA");

            SealVerifier.VerificationResult result = SealVerifier.verify(log, TEST_CHAIN);

            assertThat(result.isValid()).isFalse();
            assertThat(result.sealValid()).isFalse();
        }

        @Test
        @DisplayName("A leaf not yet valid at the sealing time (defaults to now) fails")
        void shouldRejectNotYetValidLeaf() throws Exception {
            Leaf leaf = leafFromTestCa(CNNIC_ATI_LEAF_SUBJECT, daysAhead(1), daysAhead(30));
            TransparencyLog log = certSignedLog(leaf, "SHA-256withRSA");

            SealVerifier.VerificationResult result = SealVerifier.verify(log, TEST_CHAIN);

            assertThat(result.isValid()).isFalse();
            assertThat(result.sealValid()).isFalse();
        }

        @Test
        @DisplayName("A leaf with the wrong Subject fails even though it chains to the CA")
        void shouldRejectWrongSubjectLeaf() throws Exception {
            X500Name wrongSubject = new X500Name("C=CN, O=Evil Corp, OU=NotATI, CN=impersonator");
            Leaf leaf = leafFromTestCa(wrongSubject, daysAgo(1), daysAhead(365));
            TransparencyLog log = certSignedLog(leaf, "SHA-256withRSA");

            SealVerifier.VerificationResult result = SealVerifier.verify(log, TEST_CHAIN);

            assertThat(result.isValid()).isFalse();
            assertThat(result.sealValid()).isFalse();
            assertThat(result.failureReason()).contains("Subject");
        }

        @Test
        @DisplayName("A leaf that does not chain to the injected anchor fails")
        void shouldRejectLeafFromWrongAnchor() throws Exception {
            OtherChain other = OtherChain.generate();
            Leaf leaf = other.leaf(CNNIC_ATI_LEAF_SUBJECT, daysAgo(1), daysAhead(365));
            TransparencyLog log = certSignedLog(leaf, "SHA-256withRSA");

            // Sanity: it verifies against its own anchor...
            assertThat(SealVerifier.verify(log, other.trustChain()).isValid()).isTrue();
            // ...but not against the SDK test chain (a different, absent anchor).
            SealVerifier.VerificationResult result = SealVerifier.verify(log, TEST_CHAIN);

            assertThat(result.isValid()).isFalse();
            assertThat(result.sealValid()).isFalse();
        }
    }

    // ==================== Shared test CA chain ====================

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
            // historical sealing time still chains under as-of validation (ADR 0012).
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

    /** An independent CA chain, used to prove a leaf from a different anchor is rejected. */
    private record OtherChain(KeyPair intermediateKey, X500Name intermediateSubject, SealTrustChain trustChain) {

        static OtherChain generate() throws Exception {
            KeyPair rootKey = generateRsaKeyPair();
            KeyPair intermediateKey = generateRsaKeyPair();
            X500Name rootSubject = new X500Name("C=CN, O=UniTrust, CN=Other Seal Root CA");
            X500Name intermediateSubject = new X500Name("C=CN, O=UniTrust, CN=Other Seal Intermediate CA");
            X509Certificate root = buildCertificate(rootSubject, rootKey.getPublic(),
                rootSubject, rootKey.getPrivate(), daysAgo(1), daysAhead(3650), true, null);
            X509Certificate intermediate = buildCertificate(intermediateSubject, intermediateKey.getPublic(),
                rootSubject, rootKey.getPrivate(), daysAgo(1), daysAhead(1825), true, 0);
            return new OtherChain(intermediateKey, intermediateSubject, SealTrustChain.of(root, intermediate));
        }

        Leaf leaf(X500Name subject, Date notBefore, Date notAfter) throws Exception {
            KeyPair keyPair = generateRsaKeyPair();
            X509Certificate cert = buildCertificate(subject, keyPair.getPublic(),
                intermediateSubject, intermediateKey.getPrivate(), notBefore, notAfter, false, null);
            return new Leaf(keyPair, cert);
        }
    }

    private static Leaf leafFromTestCa(X500Name subject, Date notBefore, Date notAfter) throws Exception {
        KeyPair keyPair = generateRsaKeyPair();
        X509Certificate cert = buildCertificate(subject, keyPair.getPublic(),
            INTERMEDIATE_SUBJECT, INTERMEDIATE_KEY.getPrivate(), notBefore, notAfter, false, null);
        return new Leaf(keyPair, cert);
    }

    // ==================== Signing helpers ====================

    /**
     * Builds a TL whose seal carries {@code leaf.certificate} and a SHA-256withRSA signature over
     * the JCS-canonicalized content. Sealing time defaults to "now" (inside the happy-path window).
     */
    private static TransparencyLog certSignedLog(Leaf leaf, String signatureAlgorithm) throws Exception {
        return certSignedLog(leaf, signatureAlgorithm, sealingTimeAt(new Date()));
    }

    /**
     * Builds a cert-based TL whose signed {@code payload.timestamp} (sealing time) is
     * {@code payloadTimestamp}, chosen independently of the leaf window; {@code null} omits it.
     */
    private static TransparencyLog certSignedLog(
            Leaf leaf, String signatureAlgorithm, String payloadTimestamp) throws Exception {
        Map<String, Object> response = readTlBody();
        applySealingTime(response, payloadTimestamp);
        byte[] canonicalBytes = canonicalSignedBytes(response);

        Map<String, Object> seal = new LinkedHashMap<>();
        seal.put("canonicalization", "RFC8785-JCS");
        seal.put("digestAlgorithm", "SHA-256");
        if (signatureAlgorithm != null) {
            seal.put("signatureAlgorithm", signatureAlgorithm);
        }
        seal.put("signatureEncoding", "DER_BASE64");
        seal.put("keyId", "ati-tl-rsa-v1");
        seal.put("signature", signRsa(leaf.keyPair(), canonicalBytes));
        seal.put("certificate", CertificateUtils.toPem(leaf.certificate()));
        response.put("seal", seal);

        return MAPPER.readValue(MAPPER.writeValueAsString(response), TransparencyLog.class);
    }

    /** Legacy self-asserted {@code publicKey} seal (no certificate); sealing time defaults to now. */
    private static TransparencyLog signedLog(String signatureAlgorithm) throws Exception {
        KeyPair keyPair = generateRsaKeyPair();
        Map<String, Object> response = readTlBody();
        applySealingTime(response, sealingTimeAt(new Date()));
        byte[] canonicalBytes = canonicalSignedBytes(response);

        Map<String, Object> seal = new LinkedHashMap<>();
        seal.put("canonicalization", "RFC8785-JCS");
        seal.put("digestAlgorithm", "SHA-256");
        if (signatureAlgorithm != null) {
            seal.put("signatureAlgorithm", signatureAlgorithm);
        }
        seal.put("signatureEncoding", "DER_BASE64");
        seal.put("keyId", "ati-tl-rsa-v1");
        seal.put("signature", signRsa(keyPair, canonicalBytes));
        seal.put("publicKey", toPublicKeyPem(keyPair));
        response.put("seal", seal);

        return MAPPER.readValue(MAPPER.writeValueAsString(response), TransparencyLog.class);
    }

    @SuppressWarnings("unchecked")
    private static Map<String, Object> readTlBody() throws Exception {
        return MAPPER.readValue(TL_BODY, Map.class);
    }

    /**
     * Sets the payload's {@code timestamp} (the sealing time), or removes it when {@code null}.
     * Runs before canonicalization so the chosen sealing time is covered by the Seal signature.
     */
    @SuppressWarnings("unchecked")
    private static void applySealingTime(Map<String, Object> response, String payloadTimestamp) {
        Map<String, Object> payload = (Map<String, Object>) response.get("payload");
        if (payloadTimestamp == null) {
            payload.remove("timestamp");
        } else {
            payload.put("timestamp", payloadTimestamp);
        }
    }

    /** Formats {@code time} as ISO-8601 with CNNIC's {@code +08:00} offset (production shape). */
    private static String sealingTimeAt(Date time) {
        return DateTimeFormatter.ISO_OFFSET_DATE_TIME.format(time.toInstant().atOffset(SEALING_ZONE));
    }

    private static byte[] canonicalSignedBytes(Map<String, Object> response) throws Exception {
        Map<String, Object> signedContent = new LinkedHashMap<>();
        signedContent.put("status", response.get("status"));
        signedContent.put("schemaVersion", response.get("schemaVersion"));
        signedContent.put("payload", response.get("payload"));
        signedContent.put("evidenceRef", response.get("evidenceRef"));
        return new JsonCanonicalizer(MAPPER.writeValueAsString(signedContent)).getEncodedUTF8();
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

    // ==================== Certificate generation helpers ====================

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
