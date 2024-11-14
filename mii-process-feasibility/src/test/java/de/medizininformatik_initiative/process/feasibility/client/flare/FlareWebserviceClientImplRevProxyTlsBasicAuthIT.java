package de.medizininformatik_initiative.process.feasibility.client.flare;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;

import java.io.IOException;
import java.net.URL;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.testcontainers.containers.BindMode.READ_ONLY;

@Tag("client")
@Tag("flare")
@SpringBootTest(classes = FlareWebserviceClientSpringConfig.class)
@Testcontainers
public class FlareWebserviceClientImplRevProxyTlsBasicAuthIT extends FlareWebserviceClientImplBaseIT {

    private static final String STORE_ID = "foo";

    @Autowired
    protected Map<String, FlareWebserviceClient> flareClients;

    private static URL nginxConf = getResource("nginx.conf");
    private static URL nginxTestProxyConfTemplate = getResource("reverse_proxy_tls.conf.template");
    private static URL indexFile = getResource("index.html");
    private static URL serverCertChain = getResource("../certs/server_cert_chain.pem");
    private static URL serverCertKey = getResource("../certs/server_cert_key.pem");
    private static URL trustStoreFile = getResource("../certs/ca.pem");
    private static URL passwordFile = getResource("reverse_proxy.htpasswd");
    private static URL feasibilityConfig = getResource("reverseProxy_tls_basicAuth.yml");

    @Container
    public static GenericContainer<?> proxy = new GenericContainer<>(
            DockerImageName.parse("nginx:1.27.1"))
                    .withExposedPorts(8443)
                    .withFileSystemBind(nginxConf.getPath(), "/etc/nginx/nginx.conf", READ_ONLY)
                    .withFileSystemBind(indexFile.getPath(), "/usr/share/nginx/html/index.html", READ_ONLY)
                    .withFileSystemBind(nginxTestProxyConfTemplate.getPath(),
                            "/etc/nginx/templates/default.conf.template",
                            READ_ONLY)
                    .withFileSystemBind(serverCertChain.getPath(), "/etc/nginx/certs/server_cert.pem", READ_ONLY)
                    .withFileSystemBind(serverCertKey.getPath(), "/etc/nginx/certs/server_cert_key.pem", READ_ONLY)
                    .withFileSystemBind(passwordFile.getPath(), "/etc/auth/.htpasswd", READ_ONLY)
                    .withNetwork(DEFAULT_CONTAINER_NETWORK)
                    .dependsOn(flare);

    @DynamicPropertySource
    static void dynamicProperties(DynamicPropertyRegistry registry) throws IOException {
        var proxyHost = proxy.getHost();
        var proxyPort = proxy.getFirstMappedPort();
        var config = createTempConfigFile(readFile(feasibilityConfig)
                .replaceAll("<<baseUrl>>", "https://%s:%s".formatted(proxyHost, proxyPort))
                .replaceAll("<<trustedCAFile>>", trustStoreFile.getPath())
                .replaceAll("<<storeId>>", STORE_ID));

        registry.add("de.medizininformatik_initiative.feasibility_dsf_process.configuration.file",
                () -> config.getAbsolutePath());
    }

    @Test
    void sendQuery() throws Exception {
        var rawStructuredQuery = this.getClass().getResource("valid-structured-query.json").openStream().readAllBytes();
        var feasibility = assertDoesNotThrow(() -> flareClients.get(STORE_ID).requestFeasibility(rawStructuredQuery));
        assertEquals(0, feasibility);
    }
}
