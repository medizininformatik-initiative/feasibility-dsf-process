package de.medizininformatik_initiative.process.feasibility.client.store;

import ca.uhn.fhir.context.FhirContext;
import ca.uhn.fhir.rest.api.EncodingEnum;
import ca.uhn.fhir.rest.api.RequestTypeEnum;
import ca.uhn.fhir.rest.client.apache.ApacheHttpClient;
import ca.uhn.fhir.rest.client.api.Header;
import ca.uhn.fhir.rest.client.api.IHttpClient;
import ca.uhn.fhir.rest.client.api.IHttpRequest;
import ca.uhn.fhir.rest.client.impl.RestfulClientFactory;
import ca.uhn.fhir.util.DateUtils;
import de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.apache.commons.lang3.StringUtils;
import org.apache.http.HttpHeaders;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.HttpStatus;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.config.RegistryBuilder;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.conn.socket.ConnectionSocketFactory;
import org.apache.http.conn.socket.PlainConnectionSocketFactory;
import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.ProxyAuthenticationStrategy;
import org.apache.http.impl.conn.PoolingHttpClientConnectionManager;
import org.apache.http.params.HttpParams;
import org.apache.http.protocol.HttpContext;
import org.hl7.fhir.instance.model.api.IBaseBinary;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.net.URI;
import java.time.Duration;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.concurrent.TimeUnit;
import java.util.regex.Pattern;

import javax.net.ssl.SSLContext;

import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.HEADER_PREFER;
import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.HEADER_PREFER_RESPOND_ASYNC;

// TODO: doc
@Slf4j
@RequiredArgsConstructor
public class TlsClientFactory extends RestfulClientFactory {

    Logger logger = LoggerFactory.getLogger(TlsClientFactory.class);

    private CloseableHttpClient myHttpClient;

    private HttpHost myProxy;

    private final Map<String, ApacheHttpClient> clientByServerBase = new HashMap<>();

    private SSLContext sslContext;

    public TlsClientFactory(FhirContext fhirContext, SSLContext sslContext) {
        super(fhirContext);
        this.sslContext = Objects.requireNonNull(sslContext, "SSL Context must not be null.");
    }

    @Override
    protected synchronized IHttpClient getHttpClient(String serverBase) {
        return new IHttpClient() {

            @Override
            public IHttpRequest createParamRequest(FhirContext theContext, Map<String, List<String>> theParams,
                                                   EncodingEnum theEncoding) {
                return getClient().createParamRequest(theContext, theParams, theEncoding);
            }

            @Override
            public IHttpRequest createGetRequest(FhirContext theContext, EncodingEnum theEncoding) {
                return getClient().createGetRequest(theContext, theEncoding);
            }

            @Override
            public IHttpRequest createByteRequest(FhirContext theContext, String theContents, String theContentType,
                                                  EncodingEnum theEncoding) {
                return getClient().createByteRequest(theContext, theContents, theContentType, theEncoding);
            }

            @Override
            public IHttpRequest createBinaryRequest(FhirContext theContext, IBaseBinary theBinary) {
                return getClient().createBinaryRequest(theContext, theBinary);
            }

            private ApacheHttpClient getClient() {
                if (serverBase == null || serverBase.isBlank()) {
                    throw new IllegalArgumentException("Store url is not set.");
                }
                if (clientByServerBase.containsKey(serverBase)) {
                    log.debug("Reusing ApacheHttpClient for ServerBase {}", serverBase);
                    return clientByServerBase.get(serverBase);
                } else {
                    log.debug("Returning new ApacheHttpClient for ServerBase {}", serverBase);
                    var client = new ApacheHttpClient(getNativeHttpClient(), new StringBuilder(serverBase),
                            null, null, null, null);
                    clientByServerBase.put(serverBase, client);
                    return client;
                }
            }
        };
    }

    @Override
    public synchronized IHttpClient getHttpClient(StringBuilder theUrl, Map<String, List<String>> theIfNoneExistParams,
                                                  String theIfNoneExistString, RequestTypeEnum theRequestType,
                                                  List<Header> theHeaders) {
        return new ApacheHttpClient(new AsyncHttpClient(getNativeHttpClient(), getSocketTimeout()), theUrl,
                theIfNoneExistParams, theIfNoneExistString, theRequestType, theHeaders);
    }

    public CloseableHttpClient getNativeHttpClient() {
        if (myHttpClient == null) {
            myHttpClient = getNativeHttpClientBuilder().build();
        }

        return myHttpClient;
    }

    public HttpClientBuilder getNativeHttpClientBuilder() {
        var sslContext = getSslContext();

        var socketFactoryRegistry = RegistryBuilder.<ConnectionSocketFactory>create()
                .register("http", PlainConnectionSocketFactory.getSocketFactory())
                .register("https", new SSLConnectionSocketFactory(sslContext)).build();

        var connectionManager = new PoolingHttpClientConnectionManager(
                socketFactoryRegistry, null, null, null, 5000,
                TimeUnit.MILLISECONDS);

        connectionManager.setMaxTotal(getPoolMaxTotal());
        connectionManager.setDefaultMaxPerRoute(getPoolMaxPerRoute());

        var defaultRequestConfig = RequestConfig.custom().setSocketTimeout(getSocketTimeout())
                .setConnectTimeout(getConnectTimeout()).setConnectionRequestTimeout(getConnectionRequestTimeout())
                .setProxy(myProxy).build();

        var builder = HttpClientBuilder.create()
                .setConnectionManager(connectionManager)
                .setSSLContext(sslContext).setDefaultRequestConfig(defaultRequestConfig).disableCookieManagement();

        if (myProxy != null && StringUtils.isNotBlank(getProxyUsername())
                && StringUtils.isNotBlank(getProxyPassword())) {
            CredentialsProvider credsProvider = new BasicCredentialsProvider();
            credsProvider.setCredentials(new AuthScope(myProxy.getHostName(), myProxy.getPort()),
                    new UsernamePasswordCredentials(getProxyUsername(), getProxyPassword()));
            builder.setProxyAuthenticationStrategy(new ProxyAuthenticationStrategy());
            builder.setDefaultCredentialsProvider(credsProvider);
        }
        return builder;
    }

    protected SSLContext getSslContext() {
        return sslContext;
    }

    @Override
    protected void resetHttpClient() {
        this.myHttpClient = null;
    }

    /**
     * Only allows to set an instance of type org.apache.http.client.HttpClient
     *
     * @see ca.uhn.fhir.rest.client.api.IRestfulClientFactory#setHttpClient(Object)
     */
    @Override
    public synchronized void setHttpClient(Object theHttpClient) {
        this.myHttpClient = (CloseableHttpClient) theHttpClient;
    }

    @Override
    public void setProxy(String theHost, Integer thePort) {
        if (theHost != null) {
            myProxy = new HttpHost(theHost, thePort, "http");
        } else {
            myProxy = null;
        }
    }

    private final class AsyncHttpClient extends CloseableHttpClient {
        private static final int WAIT_DURATION_MAX_MS = 30000;
        private static final int WAIT_DURATION_MIN_MS = 250;
        private static final Pattern NUMBER_PATTERN = Pattern.compile("\\d+");
        private CloseableHttpClient client;
        private Logger logger = LoggerFactory.getLogger(AsyncHttpClient.class);
        private Integer timeoutMs;

        public AsyncHttpClient(CloseableHttpClient client, Integer timeoutMs) {
            this.client = client;
            this.timeoutMs = timeoutMs;
        }

        @Override
        public void close() throws IOException {
            client.close();
        }

        @Override
        public HttpParams getParams() {
            return client.getParams();
        }

        @Override
        public ClientConnectionManager getConnectionManager() {
            return client.getConnectionManager();
        }

        @Override
        protected CloseableHttpResponse doExecute(HttpHost target, HttpRequest request, HttpContext context)
                throws IOException, ClientProtocolException {
            var response = client.execute(target, request, context);
            if (request.containsHeader(HEADER_PREFER)
                    && request.getFirstHeader(HEADER_PREFER).getValue().equals(HEADER_PREFER_RESPOND_ASYNC)
                    && response.getStatusLine().getStatusCode() == HttpStatus.SC_ACCEPTED
                    && response.containsHeader(HttpHeaders.CONTENT_LOCATION)) {
                return pollStatus(request, context, response);
            } else {
                return response;
            }
        }

        private CloseableHttpResponse pollStatus(HttpRequest originalRequest, HttpContext context,
                                                     CloseableHttpResponse response)
                throws IOException, ClientProtocolException {
            var location = URI.create(response.getFirstHeader(HttpHeaders.CONTENT_LOCATION).getValue());
            var statusTarget = HttpHost
                    .create(location.getScheme() + "://" + location.getHost() + ":" + location.getPort());
            var request = replaceUri(originalRequest, location);
            var waitDuration = Duration.ZERO;
            var startTime = System.currentTimeMillis();

            do {
                try {
                    response.close();
                    Thread.sleep(waitDuration.toMillis());

                    var deltaTimeMs = System.currentTimeMillis() - startTime;

                    if (deltaTimeMs > timeoutMs) {
                        logger.error("Polling status of asynchronous request at {} timed out after {} ms"
                                + " (timeout limit: {} ms)", location, deltaTimeMs, timeoutMs);
                        return deleteAsyncRequest(statusTarget, request, context);
                    }
                    response = client.execute(statusTarget, request, context);
                    waitDuration = nextWaitDuration(response, waitDuration, location);
                    logger.debug("Response to polling status of asynchronous request at {}: {}", location,
                            response);
                } catch (InterruptedException e) {
                    logger.error("Polling status of asynchronous request at {} interrupted: {}", location,
                            e.getMessage());
                    return deleteAsyncRequest(statusTarget, request, context);
                }
            } while (response.getStatusLine().getStatusCode() == HttpStatus.SC_ACCEPTED);

            return response;
        }

        private HttpUriRequest replaceUri(HttpRequest originalRequest, URI location) {
            return RequestBuilder.copy(originalRequest)
                    .setUri(location)
                    .build();
        }

        private CloseableHttpResponse deleteAsyncRequest(HttpHost statusTarget, HttpUriRequest request,
                                                      HttpContext context) {
            try {
                var builder = RequestBuilder.delete(request.getURI());
                Arrays.asList(request.getAllHeaders()).forEach(builder::addHeader);
                var deleteRequest = builder.build();
                var response = client.execute(statusTarget, deleteRequest, context);
                if (response.getStatusLine().getStatusCode() == HttpStatus.SC_ACCEPTED) {
                    logger.info("Asynchronous request at {} cancelled", request.getURI());
                    return response;
                } else {
                    logger.error("Failed to cancel asynchronous request at {}", request.getURI());
                    return response;
                }
            } catch (IOException e) {
                throw new RuntimeException("Failed to cancel asynchronous request at %s".formatted(request.getURI()),
                        e);
            }
        }

        private Duration nextWaitDuration(CloseableHttpResponse response, Duration previousWaitDuration, URI location) {
            if (response.containsHeader(HttpHeaders.RETRY_AFTER)) {
                var retryHeader = response.getFirstHeader(HttpHeaders.RETRY_AFTER);
                return Optional.ofNullable(retryHeader)
                        .map(h -> h.getValue())
                        .map(DateUtils::parseDate)
                        .map(Date::getTime)
                        .map(t -> Duration.ofMillis(t - System.currentTimeMillis()))
                        .orElseGet(() -> Optional.ofNullable(retryHeader)
                                .map(h -> h.getValue())
                                .filter(h -> NUMBER_PATTERN.matcher(h).matches())
                                .map(Long::parseLong)
                                .map(Duration::ofSeconds)
                                .orElseGet(() -> {
                                    logger.error("Response from {} contains invalid Retry-After header value: {}",
                                            location,
                                            retryHeader.getValue());
                                    return exponentialWaitDuration(previousWaitDuration);
                                }));
            } else {
                return exponentialWaitDuration(previousWaitDuration);
            }
        }

        private Duration exponentialWaitDuration(Duration previousWaitDuration) {
            return Duration.ofMillis(Math.min(WAIT_DURATION_MAX_MS,
                    Math.max(WAIT_DURATION_MIN_MS, previousWaitDuration.toMillis() * 2)));
        }
    }
}
