package de.medizininformatik_initiative.process.feasibility.client.flare;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.AbstractWaitStrategy;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

import java.io.IOException;
import java.net.URI;
import java.net.URL;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse.BodyHandlers;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.testcontainers.containers.BindMode.READ_ONLY;

@Tag("client")
@Tag("flare")
@SpringBootTest(classes = FlareWebserviceClientSpringConfig.class)
@Testcontainers
public class FlareWebserviceClientImplRevProxyOAuthIT extends FlareWebserviceClientImplBaseIT {

    private static final String STORE_ID = "foo";

    @Autowired
    protected Map<String, FlareWebserviceClient> flareClients;

    private static URL nginxConf = getResource("nginx.conf");
    private static URL nginxTestProxyConfTemplate = getResource("keycloak_reverse_proxy.conf.template");
    private static URL indexFile = getResource("index.html");
    private static URL serverCertChain = getResource("../certs/server_cert_chain.pem");
    private static URL serverCertKey = getResource("../certs/server_cert_key.pem");
    private static URL trustStoreFile = getResource("../certs/ca.pem");


    @Container
    public static KeycloakContainer keycloak = new KeycloakContainer("quay.io/keycloak/keycloak:25.0")
            .withNetwork(DEFAULT_CONTAINER_NETWORK)
            .withNetworkAliases("keycloak")
            .withAdminUsername("admin")
            .withAdminPassword("admin")
            .withEnv("KC_PROXY_HEADERS", "xforwarded")
            .withRealmImportFile("de/medizininformatik_initiative/process/feasibility/client/store/realm-test.json")
            .withReuse(true);

    @Container
    public static GenericContainer<?> proxy = new GenericContainer<>(
            DockerImageName.parse("nginx:1.27.1"))
                    .withExposedPorts(8443)
                    .withNetworkAliases("proxy")
                    .withFileSystemBind(nginxConf.getPath(), "/etc/nginx/nginx.conf", READ_ONLY)
                    .withFileSystemBind(indexFile.getPath(), "/usr/share/nginx/html/index.html", READ_ONLY)
                    .withFileSystemBind(nginxTestProxyConfTemplate.getPath(),
                            "/etc/nginx/templates/default.conf.template",
                            READ_ONLY)
                    .withFileSystemBind(serverCertChain.getPath(), "/etc/nginx/certs/server_cert.pem", READ_ONLY)
                    .withFileSystemBind(serverCertKey.getPath(), "/etc/nginx/certs/server_cert_key.pem", READ_ONLY)
                    .withNetwork(DEFAULT_CONTAINER_NETWORK)
                    .dependsOn(flare);

    @DynamicPropertySource
    static void dynamicProperties(DynamicPropertyRegistry registry) throws IOException {
        var flareHost = "localhost";
        var flarePort = 44180;
        var proxyHost = proxy.getHost();
        var proxyPort = proxy.getFirstMappedPort();
        var config = """
                stores:
                  ${STORE_ID}:
                    baseUrl: ${BASE_URL}
                    evaluationStrategy: ccdl
                    trustedCACertificates: ${TRUST_STORE_FILE}
                    oAuth:
                      issuerUrl: ${ISSUER_URL}
                      clientId: ${CLIENT_ID}
                      clientPassword: ${CLIENT_SECRET}
                networks:
                  foo.bar:
                    obfuscate: false
                    stores:
                    - ${STORE_ID}
                """;

        registry.add("de.medizininformatik_initiative.feasibility_dsf_process.configuration", () -> config);
        registry.add("STORE_ID", () -> STORE_ID);
        registry.add("BASE_URL", () -> "http://%s:%s".formatted(flareHost, flarePort));
        registry.add("TRUST_STORE_FILE", () -> trustStoreFile.getPath());
        registry.add("ISSUER_URL", () -> "https://%s:%s/realms/test".formatted(proxyHost, proxyPort));
        registry.add("CLIENT_ID", () -> "account");
        registry.add("CLIENT_SECRET", () -> "test");
    }

    @Test
    void sendQuery() throws Exception {

        try (GenericContainer<?> oAuth2Proxy = new GenericContainer<>(
                DockerImageName.parse("quay.io/oauth2-proxy/oauth2-proxy:v7.7.1"))
                        .withNetworkMode("host")
                        .withCopyFileToContainer(MountableFile.forHostPath(trustStoreFile.getPath()),
                                "/secrets/trusted_cas.pem")
                        .withEnv("OAUTH2_PROXY_HTTP_ADDRESS", "http://0.0.0.0:44180")
                        .withEnv("OAUTH2_PROXY_UPSTREAMS",
                                "http://%s:%d".formatted(flare.getHost(), flare.getFirstMappedPort()))
                        .withEnv("OAUTH2_PROXY_PROVIDER", "oidc")
                        .withEnv("OAUTH2_PROXY_PROVIDER_CA_FILES", "/secrets/trusted_cas.pem")
                        .withEnv("OAUTH2_PROXY_OIDC_ISSUER_URL",
                                "https://%s:%d/realms/test".formatted(proxy.getHost(), proxy.getFirstMappedPort()))
                        .withEnv("OAUTH2_PROXY_CLIENT_ID", "account")
                        .withEnv("OAUTH2_PROXY_CLIENT_SECRET", "foobar")
                        .withEnv("OAUTH2_PROXY_COOKIE_SECRET", "foobar0123456789")
                        .withEnv("OAUTH2_PROXY_SKIP_JWT_BEARER_TOKENS", "true")
                        .withEnv("OAUTH2_PROXY_OIDC_AUDIENCE_CLAIMS", "azp")
                        .withEnv("OAUTH2_PROXY_INSECURE_OIDC_ALLOW_UNVERIFIED_EMAIL", "true")
                        .withEnv("OAUTH2_PROXY_EMAIL_DOMAINS", "*")
                        .waitingFor(waitForHostUrl("http://localhost:44180"));) {
            var rawStructuredQuery = this.getClass().getResource("valid-structured-query.json").openStream()
                    .readAllBytes();
            oAuth2Proxy.start();
            var feasibility = assertDoesNotThrow(
                    () -> flareClients.get(STORE_ID).requestFeasibility(rawStructuredQuery));
            assertEquals(0, feasibility);
        }
    }

    private AbstractWaitStrategy waitForHostUrl(String url) {
        return new AbstractWaitStrategy() {

            @Override
            protected void waitUntilReady() {
                try {
                    var request = HttpRequest.newBuilder(URI.create(url))
                            .GET()
                            .build();
                    var client = HttpClient.newHttpClient();
                    var retries = 0;
                    var statusCode = 0;

                    while (statusCode != 403 && retries < 10) {
                        if (retries > 0) {
                            Thread.sleep(500);
                        }
                        try {
                            statusCode = client.send(request, BodyHandlers.ofString()).statusCode();
                        } catch (IOException e) {
                            statusCode = 0;
                        }
                        retries++;
                    }
                } catch (InterruptedException e) {
                    throw new RuntimeException("Waiting for oauth2-proxy cancelled.", e);
                }
            }
        };
    }
}
