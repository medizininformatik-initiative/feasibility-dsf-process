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
public class FlareWebserviceClientImplFwdProxyBasicAuthRevProxyBearerTokenAuthIT extends FlareWebserviceClientImplBaseIT {

    private static final String STORE_ID = "foo";

    @Autowired
    protected Map<String, FlareWebserviceClient> flareClients;

    private static URL nginxConf = getResource("nginx.conf");
    private static URL nginxTestProxyConfTemplate = getResource("reverse_proxy_bearer_token_auth.conf.template");
    private static URL indexFile = getResource("index.html");
    private static URL squidProxyConf = getResource("forward_proxy_basic_auth.conf");
    private static URL forwardProxyPasswordFile = getResource("forward_proxy.htpasswd");
    private static URL feasibilityConfig = getResource("forwardProxy_basicAuth_reverseProxy_bearerToken.yml");
    private static String bearerToken = "1234";

    @Container
    public static GenericContainer<?> proxy = new GenericContainer<>(
            DockerImageName.parse("nginx:1.27.1"))
                    .withExposedPorts(8080)
                    .withFileSystemBind(nginxConf.getPath(), "/etc/nginx/nginx.conf", READ_ONLY)
                    .withFileSystemBind(indexFile.getPath(), "/usr/share/nginx/html/index.html", READ_ONLY)
                    .withFileSystemBind(nginxTestProxyConfTemplate.getPath(),
                            "/etc/nginx/templates/default.conf.template",
                            READ_ONLY)
                    .withNetwork(DEFAULT_CONTAINER_NETWORK)
                    .withNetworkAliases("proxy")
                    .dependsOn(flare);
    @Container
    public static GenericContainer<?> forwardProxy = new GenericContainer<>(
            DockerImageName.parse("ubuntu/squid:6.6-24.04_edge"))
                    .withExposedPorts(8080)
                    .withFileSystemBind(squidProxyConf.getPath(), "/etc/squid/squid.conf", READ_ONLY)
                    .withFileSystemBind(forwardProxyPasswordFile.getPath(), "/etc/squid/passwd", READ_ONLY)
                    .withNetwork(DEFAULT_CONTAINER_NETWORK)
                    .dependsOn(proxy);

    @DynamicPropertySource
    static void dynamicProperties(DynamicPropertyRegistry registry) throws IOException {
        var proxyHost = forwardProxy.getHost();
        var proxyPort = forwardProxy.getFirstMappedPort();
        var config = createTempConfigFile(readFile(feasibilityConfig)
                .replaceAll("<<baseUrl>>", "http://proxy:8080/")
                .replaceAll("<<proxyHost>>", proxyHost)
                .replaceAll("<<proxyPort>>", proxyPort.toString())
                .replaceAll("<<proxyUsername>>", "test")
                .replaceAll("<<proxyPassword>>", "bar")
                .replaceAll("<<token>>", bearerToken)
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
