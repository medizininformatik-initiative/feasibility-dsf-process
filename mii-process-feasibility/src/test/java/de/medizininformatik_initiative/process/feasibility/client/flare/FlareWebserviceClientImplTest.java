package de.medizininformatik_initiative.process.feasibility.client.flare;

import de.medizininformatik_initiative.process.feasibility.EvaluationSettingsProviderImpl;
import de.medizininformatik_initiative.process.feasibility.EvaluationStrategy;
import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.BasicResponseHandler;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Captor;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.test.util.ReflectionTestUtils;

import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.time.Duration;

import static jakarta.ws.rs.HttpMethod.POST;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
public class FlareWebserviceClientImplTest {

    private HttpClient httpClient;
    private URI flareBaseUrl;
    private FlareWebserviceClient flareWebserviceClient;
    @Captor
    ArgumentCaptor<HttpPost> postCaptor;

    @BeforeEach
    public void setUp() throws URISyntaxException {
        httpClient = mock(HttpClient.class);
        flareBaseUrl = new URI("http://localhost:5000/");
        flareWebserviceClient = new FlareWebserviceClientImpl(httpClient, flareBaseUrl);
    }

    @Test
    public void testRequestFeasibility_FailsOnCommunicationError() throws IOException, InterruptedException {
        when(httpClient.execute(any(HttpPost.class), any(BasicResponseHandler.class)))
                .thenThrow(IOException.class);

        var structuredQuery = "foo".getBytes();
        assertThrows(IOException.class, () -> flareWebserviceClient.requestFeasibility(structuredQuery));
    }

    @Test
    public void testRequestFeasibility_FailsOnWrongBodyContent() throws IOException, InterruptedException {
        var response = "{\"invalid\": true}";
        when(httpClient.execute(any(HttpPost.class), any(BasicResponseHandler.class)))
                .thenReturn(response);

        var structuredQuery = "foo".getBytes();
        assertThrows(NumberFormatException.class, () -> flareWebserviceClient.requestFeasibility(structuredQuery));
    }

    @Test
    public void testRequestFeasibility() throws IOException, InterruptedException {
        var response = "15";
        when(httpClient.execute(any(HttpPost.class), any(BasicResponseHandler.class)))
                .thenReturn(response);

        var structuredQuery = "foo".getBytes();
        var feasibility = flareWebserviceClient.requestFeasibility(structuredQuery);

        assertEquals(15, feasibility);
    }

    @Test
    public void testBaseUrlPathIsKept() throws Exception {
        var path = "/foo/bar/";
        flareWebserviceClient = new FlareWebserviceClientImpl(httpClient, URI.create("http://foo.bar:1234" + path));
        var structuredQuery = "foo".getBytes();

        when(httpClient.execute(postCaptor.capture(), any(BasicResponseHandler.class)))
                .thenReturn("99");

        flareWebserviceClient.requestFeasibility(structuredQuery);

        assertEquals(path + "query/execute", postCaptor.getValue().getURI().getPath());
    }

    @Test
    void testNullBaseUrlDoesNotFailAtInit() throws Exception {
        var config = new FlareWebserviceClientSpringConfig();
        assertDoesNotThrow(() -> {
            return config.flareWebserviceClient(httpClient, new EvaluationSettingsProviderImpl(
                    EvaluationStrategy.STRUCTURED_QUERY, true,
                    0d, 0d, 0, Duration.ofMillis(1), false,
                    "medizininformatik-initiative.de", "medizininformatik-initiative.de",false));
        });
    }

    @Test
    void testNullBaseUrlFails() throws Exception {
        var config = new FlareWebserviceClientSpringConfig();
        var structuredQuery = "foo".getBytes();
        flareWebserviceClient = config.flareWebserviceClient(httpClient, new EvaluationSettingsProviderImpl(
                EvaluationStrategy.STRUCTURED_QUERY, true, 0d,
                0d, 0, Duration.ofMillis(1),
                false, "medizininformatik-initiative.de",
                "medizininformatik-initiative.de",false));

        var e = assertThrows(IllegalArgumentException.class,
                () -> flareWebserviceClient.requestFeasibility(structuredQuery));

        assertEquals("FLARE_BASE_URL is not set.", e.getMessage());
    }

    @Test
    void testIllegalBaseUrlFails() throws Exception {
        var config = new FlareWebserviceClientSpringConfig();
        var invalidUrl = "{ßöäü;";
        var structuredQuery = "foo".getBytes();
        ReflectionTestUtils.setField(config, "flareBaseUrl", invalidUrl);
        flareWebserviceClient = config.flareWebserviceClient(httpClient, new EvaluationSettingsProviderImpl(
                EvaluationStrategy.STRUCTURED_QUERY, true, 0d, 0d, 0, Duration.ofMillis(1), false,
                "medizininformatik-initiative.de", "medizininformatik-initiative.de",false));

        var e = assertThrows(IllegalArgumentException.class,
                () -> flareWebserviceClient.requestFeasibility(structuredQuery));

        assertEquals("Could not parse FLARE_BASE_URL '" + invalidUrl + "' as URI.", e.getMessage());
    }

    @Test
    void testOtherEvaluationStrategyFails() throws Exception {
        var config = new FlareWebserviceClientSpringConfig();
        var invalidUrl = "{ßöäü;";
        var structuredQuery = "foo".getBytes();
        ReflectionTestUtils.setField(config, "flareBaseUrl", invalidUrl);
        flareWebserviceClient = config.flareWebserviceClient(httpClient, new EvaluationSettingsProviderImpl(
                EvaluationStrategy.CQL, true, 0d,
                0d, 0, Duration.ofMillis(1), false,
                "medizininformatik-initiative.de", "medizininformatik-initiative.de",false));

        var e = assertThrows(IllegalStateException.class,
                () -> flareWebserviceClient.requestFeasibility(structuredQuery));

        assertEquals("EVALUATION_STRATEGY is not set to 'structured-query'.", e.getMessage());
    }

    @Test
    void sendErrorGetsRethrownWithAdditionalInformation() throws Exception {
        var structuredQuery = "foo".getBytes();
        var error = new IOException("error-151930");
        when(httpClient.execute(any(HttpPost.class), any(BasicResponseHandler.class))).thenThrow(error);

        assertThatThrownBy(() -> {
            flareWebserviceClient.requestFeasibility(structuredQuery);
        })
                .hasMessage("Error sending %s request to flare webservice url '%s'.", POST,
                        flareBaseUrl.resolve("/query/execute"))
                .hasCause(error);
    }
}
