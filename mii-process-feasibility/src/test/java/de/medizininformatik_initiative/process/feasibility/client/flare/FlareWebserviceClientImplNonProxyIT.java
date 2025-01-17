package de.medizininformatik_initiative.process.feasibility.client.flare;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.io.IOException;
import java.net.URL;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;

@Tag("client")
@Tag("flare")
@SpringBootTest(classes = FlareWebserviceClientSpringConfig.class)
@Testcontainers
public class FlareWebserviceClientImplNonProxyIT extends FlareWebserviceClientImplBaseIT {

    private static final String STORE_ID = "foo";

    private static URL feasibilityConfig = getResource("nonProxy.yml");

    @Autowired protected Map<String, FlareWebserviceClient> flareClients;

    @DynamicPropertySource
    static void dynamicProperties(DynamicPropertyRegistry registry) throws IOException {
        var flareHost = flare.getHost();
        var flarePort = flare.getFirstMappedPort();

        registry.add("de.medizininformatik_initiative.feasibility_dsf_process.configuration.file",
                () -> feasibilityConfig.getPath());
        registry.add("STORE_ID", () -> "foo");
        registry.add("BASE_URL", () -> "http://%s:%s/".formatted(flareHost, flarePort));
    }

    @Test
    public void sendQuery() throws IOException {
        var rawStructuredQuery = this.getClass().getResource("valid-structured-query.json")
                .openStream().readAllBytes();

        var feasibility = assertDoesNotThrow(() -> flareClients.get(STORE_ID).requestFeasibility(rawStructuredQuery));
        assertEquals(0, feasibility);
    }
}
