package com.aliyun.ati.sdk.agent.verification.crl;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.CRLDistPoint;
import org.bouncycastle.asn1.x509.CRLReason;
import org.bouncycastle.asn1.x509.DistributionPoint;
import org.bouncycastle.asn1.x509.DistributionPointName;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509CRLHolder;
import org.bouncycastle.cert.X509v2CRLBuilder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Set;

/**
 * Generates mock CA, client certificates with CDP, and CRL fixtures for unit tests.
 */
public final class CrlTestFixtures {

    public static final String DEFAULT_CRL_URL = "http://127.0.0.1:9/mock-test-ca.crl";

    private CrlTestFixtures() {
    }

    public static TestCa createTestCa() throws Exception {
        return createTestCa(DEFAULT_CRL_URL);
    }

    public static TestCa createTestCa(String crlUrl) throws Exception {
        return createTestCa(crlUrl, "ATI Mock Issuing CA");
    }

    public static TestCa createTestCa(String crlUrl, String commonName) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        KeyPair keyPair = keyGen.generateKeyPair();

        X500Name subject = new X500Name("CN=" + commonName + ", O=Test, C=CN");
        BigInteger serial = BigInteger.valueOf(1);
        Instant now = Instant.now();

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
            subject,
            serial,
            Date.from(now.minus(1, ChronoUnit.DAYS)),
            Date.from(now.plus(3650, ChronoUnit.DAYS)),
            subject,
            keyPair.getPublic()
        );
        certBuilder.addExtension(Extension.basicConstraints, true, new BasicConstraints(true));
        certBuilder.addExtension(Extension.keyUsage, true,
            new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign));
        if (crlUrl != null) {
            addCdpExtension(certBuilder, crlUrl);
        }

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
            .build(keyPair.getPrivate());
        X509Certificate certificate = new JcaX509CertificateConverter()
            .getCertificate(certBuilder.build(signer));

        return new TestCa(keyPair, certificate, crlUrl);
    }

    public static ClientCert createClientCert(TestCa ca, BigInteger serial, String crlUrl) throws Exception {
        return createClientCert(ca, serial, crlUrl, null);
    }

    /**
     * Creates a mock client Identity Certificate with optional CDP and ATI URI SAN.
     *
     * @param atiUriSan URI SAN value (e.g. {@code ati://v1.client-agent.example.com}); may be null
     */
    public static ClientCert createClientCert(
            TestCa ca,
            BigInteger serial,
            String crlUrl,
            String atiUriSan) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        KeyPair keyPair = keyGen.generateKeyPair();

        X500Name subject = new X500Name("CN=Mock Client, O=Test, C=CN");
        Instant now = Instant.now();

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
            ca.subject(),
            serial,
            Date.from(now.minus(1, ChronoUnit.HOURS)),
            Date.from(now.plus(30, ChronoUnit.DAYS)),
            subject,
            keyPair.getPublic()
        );
        if (crlUrl != null) {
            addCdpExtension(certBuilder, crlUrl);
        }
        if (atiUriSan != null) {
            GeneralName uriGeneralName = new GeneralName(GeneralName.uniformResourceIdentifier, atiUriSan);
            GeneralNames subjectAltNames = new GeneralNames(uriGeneralName);
            certBuilder.addExtension(Extension.subjectAlternativeName, false, subjectAltNames);
        }

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
            .build(ca.keyPair().getPrivate());
        X509Certificate certificate = new JcaX509CertificateConverter()
            .getCertificate(certBuilder.build(signer));

        return new ClientCert(keyPair, certificate, serial);
    }

    public static ClientCert createClientCertWithMalformedCdpExtension(TestCa ca, BigInteger serial) throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("EC");
        keyGen.initialize(256);
        KeyPair keyPair = keyGen.generateKeyPair();

        X500Name subject = new X500Name("CN=Mock Client, O=Test, C=CN");
        Instant now = Instant.now();

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
            ca.subject(),
            serial,
            Date.from(now.minus(1, ChronoUnit.HOURS)),
            Date.from(now.plus(30, ChronoUnit.DAYS)),
            subject,
            keyPair.getPublic()
        );
        certBuilder.addExtension(Extension.cRLDistributionPoints, false, new byte[] { 1, 2, 3 });

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
            .build(ca.keyPair().getPrivate());
        X509Certificate certificate = new JcaX509CertificateConverter()
            .getCertificate(certBuilder.build(signer));

        return new ClientCert(keyPair, certificate, serial);
    }

    public static ClientCert createClientCertWithLdapOnlyCdp(TestCa ca, BigInteger serial) throws Exception {
        return createClientCert(ca, serial, "ldap://crl.example.test/cn=MockCA");
    }

    public static byte[] createCrlBytes(TestCa ca, Instant nextUpdate, Set<BigInteger> revokedSerials)
            throws Exception {
        Instant now = Instant.now();
        X509v2CRLBuilder crlBuilder = new X509v2CRLBuilder(
            ca.subject(),
            Date.from(now.minus(1, ChronoUnit.HOURS))
        );
        crlBuilder.setNextUpdate(Date.from(nextUpdate));
        for (BigInteger revokedSerial : revokedSerials) {
            crlBuilder.addCRLEntry(revokedSerial, Date.from(now), CRLReason.unspecified);
        }

        ContentSigner signer = new JcaContentSignerBuilder("SHA256withECDSA")
            .build(ca.keyPair().getPrivate());
        X509CRLHolder crlHolder = crlBuilder.build(signer);
        return crlHolder.getEncoded();
    }

    public static X509CRL createCrl(TestCa ca, Instant nextUpdate, Set<BigInteger> revokedSerials)
            throws Exception {
        byte[] bytes = createCrlBytes(ca, nextUpdate, revokedSerials);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        return (X509CRL) cf.generateCRL(new ByteArrayInputStream(bytes));
    }

    private static void addCdpExtension(X509v3CertificateBuilder certBuilder, String crlUrl) throws Exception {
        DistributionPointName dpn = new DistributionPointName(
            new GeneralNames(new GeneralName(GeneralName.uniformResourceIdentifier, crlUrl)));
        DistributionPoint dp = new DistributionPoint(dpn, null, null);
        CRLDistPoint crlDistPoint = new CRLDistPoint(new DistributionPoint[] { dp });
        certBuilder.addExtension(Extension.cRLDistributionPoints, false, crlDistPoint);
    }

    public record TestCa(KeyPair keyPair, X509Certificate certificate, String crlUrl) {
        public X500Name subject() {
            return X500Name.getInstance(certificate.getSubjectX500Principal().getEncoded());
        }
    }

    public record ClientCert(KeyPair keyPair, X509Certificate certificate, BigInteger serial) {
    }
}
