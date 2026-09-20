package com.aliyun.ati.sdk.transparency.verification;

import com.aliyun.ati.sdk.crypto.CertificateUtils;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * Tests for the {@link SealTrustChain} loader (spec Seam 2): the shipped classpath chain and the
 * operator override that replaces it.
 *
 * <p>Mirrors {@code IdcaChainTest}: the shipped production chain is locked down by <b>exact CN</b>
 * so a Test/pre-release chain can never be embedded by accident, and the override is validated as
 * a well-formed Root + Intermediate pair before use (fail-closed on a malformed override).</p>
 */
class SealTrustChainTest {

    /** Exact production Seal CA Root CN — blocks any Test/pre-release root. */
    private static final String EXPECTED_ROOT_CN = "UCA RSA Non-Public Root CA - G1";

    /** Exact production Seal CA Intermediate CN — blocks any Test/pre-release intermediate. */
    private static final String EXPECTED_INTERMEDIATE_CN = "UCA RSA Non-Public CA - SHA256 - G1";

    /** The leaf Seal Certificate CN that must NOT be shipped (it rotates ~yearly). */
    private static final String LEAF_CN = "cnnic-ati-tl-service";

    private static final String SHIPPED_RESOURCE =
        "/com/aliyun/ati/sdk/transparency/seal/seal-ca-chain.crt";

    // ==================== shipped() ====================

    @Test
    @DisplayName("Shipped chain carries the exact production Root + Intermediate CNs")
    void shippedChainHasExactProductionCns() {
        SealTrustChain chain = SealTrustChain.shipped();

        assertThat(cn(chain.root())).isEqualTo(EXPECTED_ROOT_CN);
        assertThat(cn(chain.intermediate())).isEqualTo(EXPECTED_INTERMEDIATE_CN);
    }

    @Test
    @DisplayName("Shipped root is self-signed and the intermediate is issued by that root")
    void shippedChainIsRootAndIntermediate() {
        SealTrustChain chain = SealTrustChain.shipped();

        assertThat(chain.root().getSubjectX500Principal())
            .isEqualTo(chain.root().getIssuerX500Principal());
        assertThat(chain.intermediate().getIssuerX500Principal())
            .isEqualTo(chain.root().getSubjectX500Principal());
        assertThat(SealTrustChain.isSelfSigned(chain.root())).isTrue();
        assertThat(SealTrustChain.issuedBy(chain.intermediate(), chain.root())).isTrue();
    }

    @Test
    @DisplayName("Shipped resource contains exactly two certificates and no leaf Seal Certificate")
    void shippedResourceHasExactlyTwoCertificatesNoLeaf() throws Exception {
        try (InputStream in = SealTrustChain.class.getResourceAsStream(SHIPPED_RESOURCE)) {
            assertThat(in).isNotNull();
            String pem = new String(in.readAllBytes(), StandardCharsets.US_ASCII);
            List<X509Certificate> certs = CertificateUtils.parseCertificateChain(pem);

            assertThat(certs).hasSize(2);
            assertThat(certs).extracting(SealTrustChainTest::cn)
                .containsExactlyInAnyOrder(EXPECTED_ROOT_CN, EXPECTED_INTERMEDIATE_CN)
                .doesNotContain(LEAF_CN);
        }
    }

    // ==================== resolve() — blank/null override uses shipped ====================

    @Test
    @DisplayName("Null override resolves to the shipped chain")
    void nullOverrideUsesShipped() throws Exception {
        SealTrustChain shipped = SealTrustChain.shipped();

        SealTrustChain resolved = SealTrustChain.resolve(null);

        assertThat(resolved.root().getEncoded()).isEqualTo(shipped.root().getEncoded());
        assertThat(resolved.intermediate().getEncoded()).isEqualTo(shipped.intermediate().getEncoded());
    }

    @Test
    @DisplayName("Blank override resolves to the shipped chain")
    void blankOverrideUsesShipped() throws Exception {
        SealTrustChain shipped = SealTrustChain.shipped();

        SealTrustChain resolved = SealTrustChain.resolve("   ");

        assertThat(resolved.root().getEncoded()).isEqualTo(shipped.root().getEncoded());
        assertThat(resolved.intermediate().getEncoded()).isEqualTo(shipped.intermediate().getEncoded());
    }

    // ==================== resolve() — a non-blank override replaces the shipped chain ====================

    @Test
    @DisplayName("Override replaces the shipped chain entirely (never merges)")
    void overrideReplacesShippedChainEntirely(@TempDir Path tempDir) throws Exception {
        Path override = tempDir.resolve("override.pem");
        Files.writeString(override,
            CertificateUtils.toPem(ALT_ROOT) + CertificateUtils.toPem(ALT_INTERMEDIATE),
            StandardCharsets.US_ASCII);

        SealTrustChain resolved = SealTrustChain.resolve(override.toString());
        SealTrustChain shipped = SealTrustChain.shipped();

        // The resolved pair is exactly the override...
        assertThat(resolved.root().getEncoded()).isEqualTo(ALT_ROOT.getEncoded());
        assertThat(resolved.intermediate().getEncoded()).isEqualTo(ALT_INTERMEDIATE.getEncoded());
        // ...and none of the shipped production anchor survives (replace, never merge).
        assertThat(resolved.root().getEncoded()).isNotEqualTo(shipped.root().getEncoded());
        assertThat(resolved.intermediate().getEncoded()).isNotEqualTo(shipped.intermediate().getEncoded());
    }

    @Test
    @DisplayName("Override with Intermediate before Root is still accepted")
    void overrideAcceptsReversedOrder(@TempDir Path tempDir) throws Exception {
        Path override = tempDir.resolve("reversed.pem");
        Files.writeString(override,
            CertificateUtils.toPem(ALT_INTERMEDIATE) + CertificateUtils.toPem(ALT_ROOT),
            StandardCharsets.US_ASCII);

        SealTrustChain resolved = SealTrustChain.resolve(override.toString());

        assertThat(resolved.root().getEncoded()).isEqualTo(ALT_ROOT.getEncoded());
        assertThat(resolved.intermediate().getEncoded()).isEqualTo(ALT_INTERMEDIATE.getEncoded());
    }

    // ==================== resolve() — malformed override fails closed ====================

    @Test
    @DisplayName("Override with a single certificate is rejected")
    void overrideRejectsSingleCertificate(@TempDir Path tempDir) throws Exception {
        Path override = tempDir.resolve("one.pem");
        Files.writeString(override, CertificateUtils.toPem(ALT_ROOT), StandardCharsets.US_ASCII);

        assertThatThrownBy(() -> SealTrustChain.resolve(override.toString()))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("exactly 2");
    }

    @Test
    @DisplayName("Override with three certificates is rejected")
    void overrideRejectsThreeCertificates(@TempDir Path tempDir) throws Exception {
        Path override = tempDir.resolve("three.pem");
        Files.writeString(override,
            CertificateUtils.toPem(ALT_ROOT)
                + CertificateUtils.toPem(ALT_INTERMEDIATE)
                + CertificateUtils.toPem(ALT_ROOT),
            StandardCharsets.US_ASCII);

        assertThatThrownBy(() -> SealTrustChain.resolve(override.toString()))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("exactly 2");
    }

    @Test
    @DisplayName("Override with two unrelated certificates is a chain structure error")
    void overrideRejectsUnrelatedCertificates(@TempDir Path tempDir) throws Exception {
        Path override = tempDir.resolve("two-intermediates.pem");
        Files.writeString(override,
            CertificateUtils.toPem(ALT_INTERMEDIATE) + CertificateUtils.toPem(ALT_INTERMEDIATE),
            StandardCharsets.US_ASCII);

        assertThatThrownBy(() -> SealTrustChain.resolve(override.toString()))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("must be one self-signed Root")
            .hasNoCause();
    }

    @Test
    @DisplayName("Missing override file fails closed")
    void missingOverrideFileFailsClosed(@TempDir Path tempDir) {
        Path missing = tempDir.resolve("absent.pem");

        assertThatThrownBy(() -> SealTrustChain.resolve(missing.toString()))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("Failed to read Seal CA Chain override");
    }

    @Test
    @DisplayName("Override that is not a well-formed Root + Intermediate pair fails before use")
    void malformedOverrideFailsClosed(@TempDir Path tempDir) throws Exception {
        Path override = tempDir.resolve("garbage.pem");
        Files.writeString(override, "not-a-certificate", StandardCharsets.US_ASCII);

        assertThatThrownBy(() -> SealTrustChain.resolve(override.toString()))
            .isInstanceOf(IllegalStateException.class);
    }

    // ==================== Alternate chain (drives the override cases) ====================

    private static final AtomicLong SERIAL = new AtomicLong(System.nanoTime());
    private static final X500Name ALT_ROOT_SUBJECT = new X500Name("C=CN, O=UniTrust, CN=Alt Seal Root CA");
    private static final X500Name ALT_INTERMEDIATE_SUBJECT =
        new X500Name("C=CN, O=UniTrust, CN=Alt Seal Intermediate CA");

    private static final X509Certificate ALT_ROOT;
    private static final X509Certificate ALT_INTERMEDIATE;

    static {
        try {
            KeyPair rootKey = generateRsaKeyPair();
            KeyPair intermediateKey = generateRsaKeyPair();
            ALT_ROOT = buildCertificate(ALT_ROOT_SUBJECT, rootKey.getPublic(),
                ALT_ROOT_SUBJECT, rootKey.getPrivate(), daysAgo(1), daysAhead(3650), true, null);
            ALT_INTERMEDIATE = buildCertificate(ALT_INTERMEDIATE_SUBJECT, intermediateKey.getPublic(),
                ALT_ROOT_SUBJECT, rootKey.getPrivate(), daysAgo(1), daysAhead(1825), true, 0);
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    // ==================== Helpers ====================

    /** Extracts the CN via BouncyCastle so UTF-8/PrintableString values match exactly. */
    private static String cn(X509Certificate cert) {
        X500Name subject = X500Name.getInstance(cert.getSubjectX500Principal().getEncoded());
        RDN[] rdns = subject.getRDNs(BCStyle.CN);
        if (rdns.length == 0) {
            return null;
        }
        ASN1Encodable value = rdns[0].getFirst().getValue();
        return value instanceof ASN1String ? ((ASN1String) value).getString() : String.valueOf(value);
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
