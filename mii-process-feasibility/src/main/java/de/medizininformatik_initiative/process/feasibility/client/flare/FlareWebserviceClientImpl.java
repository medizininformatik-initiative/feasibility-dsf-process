package de.medizininformatik_initiative.process.feasibility.client.flare;

import org.apache.http.client.HttpClient;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.entity.ByteArrayEntity;
import org.apache.http.impl.client.BasicResponseHandler;
import org.apache.http.message.BasicHeader;

import java.io.IOException;
import java.net.URI;

import static ca.uhn.fhir.rest.api.Constants.HEADER_CONTENT_TYPE;
import static java.lang.String.format;

/**
 * Client for communicating with a Flare instance.
 */
public class FlareWebserviceClientImpl implements FlareWebserviceClient {

    private final org.apache.http.client.HttpClient httpClient;
    private final URI flareBaseUrl;

    public FlareWebserviceClientImpl(HttpClient httpClient, URI flareBaseUrl) {
        this.httpClient = httpClient;
        this.flareBaseUrl = flareBaseUrl;
    }

    @Override
    public int requestFeasibility(byte[] structuredQuery) throws IOException, InterruptedException {
        var req = new HttpPost(resolve("/query/execute"));
        req.setEntity(new ByteArrayEntity(structuredQuery));
        req.setHeader(new BasicHeader(HEADER_CONTENT_TYPE, "application/sq+json"));

        var response = sendRequest(req);

        if (response != null && response.trim().matches("\\d+")) {
            return Integer.parseInt(response.trim());
        } else {
            throw new IOException("Non-integer response from flare webservice (url '%s'): '%s'".formatted(req.getURI(),
                    response == null ? "" : response));
        }
    }

    @Override
    public void testConnection() throws IOException {
        var req = new HttpGet(resolve("/cache/stats"));

        sendRequest(req);
    }

    private URI resolve(String path) {
        return flareBaseUrl.resolve((flareBaseUrl.getPath() + path).replaceAll("//", "/"));
    }

    private String sendRequest(HttpUriRequest req) throws IOException {
        try {
            return httpClient.execute(req, new BasicResponseHandler());
        } catch (IOException e) {
            throw new IOException(
                    format("Error sending %s request to flare webservice url '%s'.", req.getMethod(), req.getURI()), e);
        }
    }

    @Override
    public URI getFlareBaseUrl() {
        return flareBaseUrl;
    }
}
