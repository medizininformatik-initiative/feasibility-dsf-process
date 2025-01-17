package de.medizininformatik_initiative.process.feasibility.client.flare;

import de.medizininformatik_initiative.process.feasibility.client.variables.TestConstantsFeasibility;
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
public class FlareWebserviceClientImplFwdProxyBasicAuthRevProxyTlsIT extends FlareWebserviceClientImplBaseIT {

    private static final String STORE_ID = "foo";

    @Autowired
    protected Map<String, FlareWebserviceClient> flareClients;

    private static URL squidProxyConf = getResource("forward_proxy_basic_auth.conf");
    private static URL passwordFile = getResource("forward_proxy.htpasswd");
    private static URL nginxConf = getResource("nginx.conf");
    private static URL nginxTestProxyConfTemplate = getResource("reverse_proxy_tls.conf.template");
    private static URL indexFile = getResource("index.html");
    private static URL serverCertChain = getResource("../certs/server_cert_chain.pem");
    private static URL serverCertKey = getResource("../certs/server_cert_key.pem");
    private static URL trustedCAFile = getResource("../certs/ca.pem");

    @Container
    public static GenericContainer<?> proxy = new GenericContainer<>(
            DockerImageName.parse("nginx:" + TestConstantsFeasibility.NGINX_VERSION))
                    .withExposedPorts(8443)
                    .withFileSystemBind(nginxConf.getPath(), "/etc/nginx/nginx.conf", READ_ONLY)
                    .withFileSystemBind(indexFile.getPath(), "/usr/share/nginx/html/index.html", READ_ONLY)
                    .withFileSystemBind(nginxTestProxyConfTemplate.getPath(),
                            "/etc/nginx/templates/default.conf.template",
                            READ_ONLY)
                    .withFileSystemBind(serverCertChain.getPath(), "/etc/nginx/certs/server_cert.pem", READ_ONLY)
                    .withFileSystemBind(serverCertKey.getPath(), "/etc/nginx/certs/server_cert_key.pem", READ_ONLY)
                    .withNetwork(DEFAULT_CONTAINER_NETWORK)
                    .withNetworkAliases("proxy")
                    .dependsOn(flare);

    @Container
    public static GenericContainer<?> forwardProxy = new GenericContainer<>(
            DockerImageName.parse("ubuntu/squid:" + TestConstantsFeasibility.SQUID_VERSION))
                    .withExposedPorts(8080)
                    .withFileSystemBind(squidProxyConf.getPath(), "/etc/squid/squid.conf", READ_ONLY)
                    .withFileSystemBind(passwordFile.getPath(), "/etc/squid/passwd", READ_ONLY)
                    .withNetwork(DEFAULT_CONTAINER_NETWORK)
                    .dependsOn(proxy);

    @DynamicPropertySource
    static void dynamicProperties(DynamicPropertyRegistry registry) throws IOException {
        var config = """
                stores:
                  ${STORE_ID}:
                    baseUrl: https://proxy:8443/
                    evaluationStrategy: ccdl
                    trustedCACertificates: ${TRUSTED_CA_FILE}
                    proxy:
                      host: ${PROXY_HOST}
                      port: ${PROXY_PORT}
                      username: ${PROXY_USERNAME}
                      password: ${PROXY_PASSWORD}

                networks:
                  medizininformatik-initiative.de:
                    obfuscate: true
                    stores:
                    - ${STORE_ID}
                """;

        registry.add("de.medizininformatik_initiative.feasibility_dsf_process.configuration", () -> config);
        registry.add("STORE_ID", () -> STORE_ID);
        registry.add("PROXY_HOST", () -> forwardProxy.getHost());
        registry.add("PROXY_PORT", () -> forwardProxy.getFirstMappedPort());
        registry.add("PROXY_USERNAME", () -> "test");
        registry.add("PROXY_PASSWORD", () -> "bar");
        registry.add("TRUSTED_CA_FILE", () -> trustedCAFile.getPath());
    }

    @Test
    void sendQuery() throws Exception {
        var rawStructuredQuery = this.getClass().getResource("valid-structured-query.json").openStream().readAllBytes();
        var feasibility = assertDoesNotThrow(() -> flareClients.get(STORE_ID).requestFeasibility(rawStructuredQuery));
        assertEquals(0, feasibility);
    }
}
