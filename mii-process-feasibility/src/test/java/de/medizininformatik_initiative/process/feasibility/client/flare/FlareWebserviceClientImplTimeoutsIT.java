package de.medizininformatik_initiative.process.feasibility.client.flare;

import com.google.common.base.Stopwatch;
import de.medizininformatik_initiative.process.feasibility.client.variables.TestConstantsFeasibility;
import eu.rekawek.toxiproxy.Proxy;
import eu.rekawek.toxiproxy.ToxiproxyClient;
import eu.rekawek.toxiproxy.model.ToxicDirection;
import eu.rekawek.toxiproxy.model.toxic.Latency;
import org.assertj.core.api.Condition;
import org.assertj.core.description.Description;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.containers.ToxiproxyContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.io.IOException;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.time.Duration;
import java.util.Map;
import java.util.Random;
import java.util.concurrent.TimeUnit;

import static java.lang.String.format;
import static org.assertj.core.api.Assertions.assertThatNoException;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

@Tag("client")
@Tag("flare")
@SpringBootTest(classes = FlareWebserviceClientSpringConfig.class)
@Testcontainers
public class FlareWebserviceClientImplTimeoutsIT extends FlareWebserviceClientImplBaseIT {

    private static final String STORE_ID = "foo";
    private static final int PROXY_PORT = 8666;
    private static final Integer RANDOM_CLIENT_TIMEOUT = new Random().nextInt(5000, 20000);
    private static URL feasibilityConfig = getResource("nonProxy_timeout.yml");

    private Stopwatch executionTimer = Stopwatch.createUnstarted();

    @Autowired protected Map<String, FlareWebserviceClient> flareClients;

    @Container
    public static ToxiproxyContainer toxiproxy = new ToxiproxyContainer(
            "ghcr.io/shopify/toxiproxy:" + TestConstantsFeasibility.TOXIPROXY_VERSION)
            .withNetwork(DEFAULT_CONTAINER_NETWORK)
            .dependsOn(flare);
    private static ToxiproxyClient toxiproxyClient;
    private static Proxy proxy;
    private static Latency latency;

    @DynamicPropertySource
    static void dynamicProperties(DynamicPropertyRegistry registry) throws IOException {
        registry.add("de.medizininformatik_initiative.feasibility_dsf_process.configuration.file",
                () -> feasibilityConfig.getPath());
        registry.add("STORE_ID", () -> STORE_ID);
        registry.add("BASE_URL",
                () -> "http://%s:%d/".formatted(toxiproxy.getHost(), toxiproxy.getMappedPort(PROXY_PORT)));
        registry.add("TIMEOUT", () -> RANDOM_CLIENT_TIMEOUT.toString());
    }

    @BeforeAll
    static void setup() throws IOException {
        toxiproxyClient = new ToxiproxyClient(toxiproxy.getHost(), toxiproxy.getControlPort());
        proxy = toxiproxyClient.createProxy("flare", "0.0.0.0:" + PROXY_PORT,
                format("%s:%s", flare.getNetworkAliases().get(0), flare.getExposedPorts().get(0)));
        latency = proxy.toxics().latency("latency", ToxicDirection.UPSTREAM, 0);
    }

    @BeforeEach
    void startClock() {
        executionTimer.reset().start();
    }

    @Test
    @DisplayName("flare client fails getting no response after given socket timeout")
    public void requestFeasibilityWithLongerProxyTimeoutFails() throws IOException {
        var rawStructuredQuery = this.getClass().getResource("valid-structured-query.json")
                .openStream().readAllBytes();
        var proxyTimeout = RANDOM_CLIENT_TIMEOUT + 10000;
        latency.setLatency(proxyTimeout);

        assertThatThrownBy(() -> flareClients.get(STORE_ID).requestFeasibility(rawStructuredQuery))
                .describedAs(new Description() {

                    @Override
                    public String value() {
                        executionTimer.stop();
                        return format("execution time is %s ms", executionTimer.elapsed(TimeUnit.MILLISECONDS));
                    }
                })
                .isInstanceOf(IOException.class)
                .hasMessageStartingWith("Error sending POST request to flare webservice")
                .hasCauseInstanceOf(SocketTimeoutException.class)
                .is(new Condition<>(
                        _e -> Duration.ofMillis(RANDOM_CLIENT_TIMEOUT).minus(executionTimer.elapsed()).isNegative(),
                        "executed longer than client timeout of %dms", RANDOM_CLIENT_TIMEOUT))
                .is(new Condition<>(_e -> executionTimer.elapsed().minusMillis(proxyTimeout).isNegative(),
                        "executed shorter than proxy timeout of %dms", proxyTimeout));
    }

    @Test
    @DisplayName("flare client succeeds getting a response before given socket timeout")
    public void requestFeasibilityWithShorterProxyTimeoutSucceeds() throws IOException {
        var rawStructuredQuery = this.getClass().getResource("valid-structured-query.json")
                .openStream().readAllBytes();
        latency.setLatency(RANDOM_CLIENT_TIMEOUT - 2000);

        assertThatNoException().isThrownBy(() -> flareClients.get(STORE_ID).requestFeasibility(rawStructuredQuery));
    }
}
