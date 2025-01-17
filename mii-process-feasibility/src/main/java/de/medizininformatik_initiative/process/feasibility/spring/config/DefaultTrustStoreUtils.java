package de.medizininformatik_initiative.process.feasibility.spring.config;

import de.rwh.utils.crypto.CertificateHelper;
import de.rwh.utils.crypto.io.CertificateReader;
import de.rwh.utils.crypto.io.PemIo;
import org.apache.http.ssl.SSLContexts;
import org.bouncycastle.pkcs.PKCSException;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Security;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Optional;
import java.util.UUID;

import javax.net.ssl.SSLContext;

// TODO: doc
public final class DefaultTrustStoreUtils {
    private DefaultTrustStoreUtils() {
    }

    public static KeyStore loadDefaultTrustStore() {
        Path location = null;
        String type = null;
        String password = null;

        var locationProperty = System.getProperty("javax.net.ssl.trustStore");
        if ((null != locationProperty) && (locationProperty.length() > 0)) {
            var p = Paths.get(locationProperty);
            var f = p.toFile();
            if (f.exists() && f.isFile() && f.canRead()) {
                location = p;
            }
        } else {
            var javaHome = System.getProperty("java.home");
            location = Paths.get(javaHome, "lib", "security", "jssecacerts");
            if (!location.toFile().exists()) {
                location = Paths.get(javaHome, "lib", "security", "cacerts");
            }
        }

        var passwordProperty = System.getProperty("javax.net.ssl.trustStorePassword");
        if ((null != passwordProperty) && (passwordProperty.length() > 0)) {
            password = passwordProperty;
        } else {
            password = "changeit";
        }

        var typeProperty = System.getProperty("javax.net.ssl.trustStoreType");
        if ((null != typeProperty) && (typeProperty.length() > 0)) {
            type = passwordProperty;
        } else {
            type = KeyStore.getDefaultType();
        }

        KeyStore trustStore = null;
        try {
            trustStore = KeyStore.getInstance(type, Security.getProvider("SUN"));
        } catch (KeyStoreException e) {
            throw new RuntimeException(e);
        }

        try (var is = Files.newInputStream(location)) {
            trustStore.load(is, password.toCharArray());
        } catch (IOException
                 | CertificateException
                 | NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        return trustStore;
    }

    public static KeyStore loadTrustStore(String trustStorePath)
            throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
        if (trustStorePath == null || trustStorePath.isBlank()) {
            return DefaultTrustStoreUtils.loadDefaultTrustStore();
        } else {
            return CertificateReader.allFromCer(Paths.get(trustStorePath));
        }
    }

    public static KeyStore loadKeyStore(String certPath, String privateKeyPath, Optional<String> privateKeyPassword,
                                        String keyStorePassword)
            throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException, PKCSException {
        if (certPath == null || certPath.isBlank()) {
            return null;
        }
        PrivateKey privateKey = PemIo.readPrivateKeyFromPem(Paths.get(privateKeyPath),
                privateKeyPassword.map(p -> p.toCharArray()).orElse(null));
        X509Certificate cert = PemIo.readX509CertificateFromPem(Paths.get(certPath));

        return CertificateHelper.toJksKeyStore(privateKey, new Certificate[] { cert }, UUID.randomUUID().toString(),
                keyStorePassword.toCharArray());
    }

    public static SSLContext createSslContext(String trustedCAsPath, Optional<String> clientCertPath,
                                              Optional<String> clientCertPrivateKeyPath,
                                              Optional<String> privateKeyPassword)
            throws IOException, PKCSException, KeyStoreException, CertificateException, NoSuchAlgorithmException,
            UnrecoverableKeyException, KeyManagementException {
        var trustStore = loadTrustStore(trustedCAsPath);
        var sslContextBuilder = SSLContexts.custom().loadTrustMaterial(trustStore, null);
        var keyStorePassword = privateKeyPassword.orElse("");
        if (clientCertPath.isPresent() && clientCertPrivateKeyPath.isPresent()) {
            sslContextBuilder.loadKeyMaterial(loadKeyStore(clientCertPath.get(), clientCertPrivateKeyPath.get(),
                    privateKeyPassword, keyStorePassword), keyStorePassword.toCharArray());
        }
        return sslContextBuilder.build();
    }
}
