package com.aliyun.ati.sdk.agent.verification;

import com.aliyun.ati.sdk.crypto.CertificateUtils;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import javax.security.auth.x500.X500Principal;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.X509Certificate;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class IdcaChainTest {

    @Test
    @DisplayName("Shipped chain is exactly Root + Intermediate")
    void shippedChainIsRootAndIntermediate() {
        IdcaChain chain = IdcaChain.shipped();

        assertThat(chain.root().getSubjectX500Principal())
            .isEqualTo(chain.root().getIssuerX500Principal());
        assertThat(chain.intermediate().getIssuerX500Principal())
            .isEqualTo(chain.root().getSubjectX500Principal());
        assertThat(chain.root().getSubjectX500Principal().getName())
            .contains("UniTrust");
        assertThat(chain.intermediate().getSubjectX500Principal().getName())
            .contains("CNNIC");
    }

    @Test
    @DisplayName("Individual resource files match the shipped chain PEM")
    void individualResourceFilesMatchShippedChain() throws Exception {
        IdcaChain shipped = IdcaChain.shipped();
        try (var rootIn = IdcaChain.class.getResourceAsStream(
                "/com/aliyun/ati/sdk/agent/idca/idca-root.crt");
             var intermediateIn = IdcaChain.class.getResourceAsStream(
                "/com/aliyun/ati/sdk/agent/idca/idca-intermediate.crt")) {
            assertThat(rootIn).isNotNull();
            assertThat(intermediateIn).isNotNull();
            X509Certificate root = CertificateUtils.parseCertificate(
                new String(rootIn.readAllBytes(), StandardCharsets.US_ASCII));
            X509Certificate intermediate = CertificateUtils.parseCertificate(
                new String(intermediateIn.readAllBytes(), StandardCharsets.US_ASCII));
            assertThat(root.getEncoded()).isEqualTo(shipped.root().getEncoded());
            assertThat(intermediate.getEncoded()).isEqualTo(shipped.intermediate().getEncoded());
        }
    }

    @Test
    @DisplayName("Blank override resolves to shipped classpath location")
    void blankOverrideUsesShippedClasspathLocation() {
        assertThat(IdcaChain.trustCertificateLocation(null))
            .isEqualTo(IdcaChain.SHIPPED_CLASSPATH_LOCATION);
        assertThat(IdcaChain.trustCertificateLocation("  "))
            .isEqualTo(IdcaChain.SHIPPED_CLASSPATH_LOCATION);
    }

    @Test
    @DisplayName("Override path is returned after validating exactly two certificates")
    void overridePathReplacesShippedChain(@TempDir Path tempDir) throws Exception {
        IdcaChain shipped = IdcaChain.shipped();
        Path override = tempDir.resolve("override.pem");
        Files.writeString(override,
            CertificateUtils.toPem(shipped.root()) + CertificateUtils.toPem(shipped.intermediate()),
            StandardCharsets.US_ASCII);

        assertThat(IdcaChain.trustCertificateLocation(override.toString()))
            .isEqualTo(override.toString());

        IdcaChain loaded = IdcaChain.fromPemFile(override);
        assertThat(loaded.root().getEncoded()).isEqualTo(shipped.root().getEncoded());
        assertThat(loaded.intermediate().getEncoded()).isEqualTo(shipped.intermediate().getEncoded());
    }

    @Test
    @DisplayName("Override with Intermediate then Root is still accepted")
    void overrideAcceptsReversedOrder(@TempDir Path tempDir) throws Exception {
        IdcaChain shipped = IdcaChain.shipped();
        Path override = tempDir.resolve("reversed.pem");
        Files.writeString(override,
            CertificateUtils.toPem(shipped.intermediate()) + CertificateUtils.toPem(shipped.root()),
            StandardCharsets.US_ASCII);

        IdcaChain loaded = IdcaChain.fromPemFile(override);
        assertThat(loaded.root().getEncoded()).isEqualTo(shipped.root().getEncoded());
        assertThat(loaded.intermediate().getEncoded()).isEqualTo(shipped.intermediate().getEncoded());
    }

    @Test
    @DisplayName("Override with one certificate is rejected")
    void overrideRejectsSingleCertificate(@TempDir Path tempDir) throws Exception {
        X509Certificate root = IdcaChain.shipped().root();
        Path override = tempDir.resolve("one.pem");
        Files.writeString(override, CertificateUtils.toPem(root), StandardCharsets.US_ASCII);

        assertThatThrownBy(() -> IdcaChain.fromPemFile(override))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("exactly 2");
    }

    @Test
    @DisplayName("Override with three certificates is rejected")
    void overrideRejectsThreeCertificates(@TempDir Path tempDir) throws Exception {
        IdcaChain shipped = IdcaChain.shipped();
        Path override = tempDir.resolve("three.pem");
        Files.writeString(override,
            CertificateUtils.toPem(shipped.root())
                + CertificateUtils.toPem(shipped.intermediate())
                + CertificateUtils.toPem(shipped.root()),
            StandardCharsets.US_ASCII);

        assertThatThrownBy(() -> IdcaChain.fromPemFile(override))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("exactly 2");
    }

    @Test
    @DisplayName("Missing override file fails closed")
    void missingOverrideFileFailsClosed(@TempDir Path tempDir) {
        Path missing = tempDir.resolve("absent.pem");

        assertThatThrownBy(() -> IdcaChain.trustCertificateLocation(missing.toString()))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("Failed to read IDCA Chain override");
    }

    @Test
    @DisplayName("Two unrelated certificates are a chain structure error, not a provider failure")
    void unrelatedCertificatesAreStructureError(@TempDir Path tempDir) throws Exception {
        IdcaChain shipped = IdcaChain.shipped();
        Path override = tempDir.resolve("two-intermediates.pem");
        Files.writeString(override,
            CertificateUtils.toPem(shipped.intermediate())
                + CertificateUtils.toPem(shipped.intermediate()),
            StandardCharsets.US_ASCII);

        assertThatThrownBy(() -> IdcaChain.fromPemFile(override))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("must be one self-signed Root")
            .hasNoCause();
    }

    @Test
    @DisplayName("SignatureException is treated as chain structure mismatch")
    void signatureExceptionIsStructureMismatch() throws Exception {
        X509Certificate subject = mock(X509Certificate.class);
        PublicKey key = mock(PublicKey.class);
        when(subject.getPublicKey()).thenReturn(key);
        doThrow(new SignatureException("mismatch")).when(subject).verify(key);

        assertThat(IdcaChain.signatureMatches(subject, subject)).isFalse();
    }

    @Test
    @DisplayName("Missing JCE algorithm is wrapped with cause, not reported as chain structure error")
    void algorithmFailurePreservesCause() throws Exception {
        X509Certificate cert = mock(X509Certificate.class);
        PublicKey key = mock(PublicKey.class);
        X500Principal dn = new X500Principal("CN=Test");
        when(cert.getSubjectX500Principal()).thenReturn(dn);
        when(cert.getIssuerX500Principal()).thenReturn(dn);
        when(cert.getPublicKey()).thenReturn(key);
        doThrow(new NoSuchAlgorithmException("SHA256withRSA")).when(cert).verify(key);

        assertThatThrownBy(() -> IdcaChain.isSelfSigned(cert))
            .isInstanceOf(IllegalStateException.class)
            .hasMessageContaining("signature verification failed")
            .hasMessageContaining("JCE/FIPS")
            .hasCauseInstanceOf(NoSuchAlgorithmException.class)
            .hasMessageNotContaining("must be one self-signed Root");
    }
}
