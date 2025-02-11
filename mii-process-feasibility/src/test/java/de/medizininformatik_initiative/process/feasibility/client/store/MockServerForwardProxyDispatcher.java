package de.medizininformatik_initiative.process.feasibility.client.store;

import lombok.NonNull;
import okhttp3.HttpUrl;
import okhttp3.OkHttpClient;
import okhttp3.mockwebserver.MockResponse;
import okhttp3.mockwebserver.RecordedRequest;
import org.apache.http.HttpHeaders;

import java.util.regex.Pattern;

import javax.annotation.Nonnull;

import static org.apache.http.HttpHeaders.PROXY_AUTHENTICATE;

public class MockServerForwardProxyDispatcher extends MockServerProxyDispatcher {

    private static final Pattern REQUEST_LINE_URL = Pattern.compile("^(\\w+)\\s+(https?://[^\\s]+)\\s+.*$");

    public MockServerForwardProxyDispatcher(@NonNull OkHttpClient client, @NonNull HttpUrl targetServiceUrl) {
        super(client, targetServiceUrl);
    }

    @Nonnull
    @Override
    public MockResponse dispatch(@Nonnull RecordedRequest req) {
        if (req.getHeader(HttpHeaders.PROXY_AUTHORIZATION) == null) {
            return new MockResponse().setResponseCode(407).setHeader(PROXY_AUTHENTICATE, "Basic");
        } else {
            var requestLineParts = REQUEST_LINE_URL.matcher(req.getRequestLine());
            if (requestLineParts.matches()) {
                return requestTarget(HttpUrl.parse(requestLineParts.group(2)),
                        requestLineParts.group(1),
                        extractRequestBody(req),
                        req.getHeaders());
            } else {
                return failedResponse();
            }
        }
    }
}
