package de.medizininformatik_initiative.process.feasibility.client.flare;

import de.medizininformatik_initiative.process.feasibility.EvaluationStrategy;
import de.medizininformatik_initiative.process.feasibility.FeasibilitySettings;
import de.medizininformatik_initiative.process.feasibility.FeasibilitySettings.ProxySettings;
import de.medizininformatik_initiative.process.feasibility.FeasibilitySettings.StoreSettings;
import de.medizininformatik_initiative.process.feasibility.client.store.OAuthInterceptor;
import de.medizininformatik_initiative.process.feasibility.client.store.TlsClientFactory;
import de.medizininformatik_initiative.process.feasibility.spring.config.BaseConfig;
import de.medizininformatik_initiative.process.feasibility.spring.config.DefaultTrustStoreUtils;
import org.apache.http.HttpHost;
import org.apache.http.HttpRequest;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.ClientProtocolException;
import org.apache.http.client.HttpClient;
import org.apache.http.client.ResponseHandler;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.conn.ClientConnectionManager;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.ProxyAuthenticationStrategy;
import org.apache.http.message.BasicHeader;
import org.apache.http.params.HttpParams;
import org.apache.http.protocol.HttpContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;

import java.io.IOException;
import java.net.URISyntaxException;
import java.net.URL;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;

import static ca.uhn.fhir.rest.api.Constants.HEADER_AUTHORIZATION;
import static ca.uhn.fhir.rest.api.Constants.HEADER_AUTHORIZATION_VALPREFIX_BEARER;
import static com.google.common.base.Strings.isNullOrEmpty;
import static de.medizininformatik_initiative.process.feasibility.variables.ConstantsFeasibility.CLIENT_TIMEOUT_DEFAULT;

@Configuration
@Import({ BaseConfig.class })
public class FlareWebserviceClientSpringConfig {

    private static final Logger logger = LoggerFactory.getLogger(FlareWebserviceClientSpringConfig.class);

    @Bean
    public Map<String, FlareWebserviceClient> flareWebserviceClients(FeasibilitySettings feasibilitySettings) {
        return feasibilitySettings.stores().entrySet().stream()
                .filter(e -> e.getValue().evaluationStrategy() == EvaluationStrategy.CCDL)
                .collect(Collectors.toMap(e -> e.getKey(), e -> createFlareClient(e.getKey(), e.getValue())));
    }

    private FlareWebserviceClient createFlareClient(String storeId, StoreSettings store) {
        logger.info("Setting up flare client for store '{}' using {}.", storeId, EvaluationStrategy.CCDL);
        var httpClient = flareHttpClient(storeId, store);
        try {
            return new FlareWebserviceClientImpl(httpClient, store.baseUrl().toURI());
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException(
                    "Store '%s' flare base url '%s' is invalid URI.".formatted(storeId, store.baseUrl()),
                    e);
        }
    }

    public HttpClient flareHttpClient(String storeId, StoreSettings store) {
        try {
            var trustedCACertificates = store.trustedCACertificates();
            var clientCert = Optional.ofNullable(store.clientCertificate());
            var privKey = Optional.ofNullable(store.privateKey());
            var privKeyPassword = Optional.ofNullable(store.privateKeyPassword());
            var requestTimeout = Optional.ofNullable(store.requestTimeout());
            var sslContext = DefaultTrustStoreUtils.createSslContext(trustedCACertificates, clientCert, privKey,
                    privKeyPassword);
            var clientFactory = new TlsClientFactory(null, sslContext);
            clientFactory.setSocketTimeout(requestTimeout.orElse(CLIENT_TIMEOUT_DEFAULT));
            var builder = clientFactory.getNativeHttpClientBuilder();

            var credentialsProvider = new BasicCredentialsProvider();

            if (store.proxy() != null) {
                logger.info("Setting proxy (host: '{}', port: '{}') for store '{}' flare client.", store.proxy().host(),
                        store.proxy().port(), storeId);
                var proxy = new HttpHost(store.proxy().host(), store.proxy().port());
                builder.setProxy(proxy);
                if (!isNullOrEmpty(store.proxy().username()) && !isNullOrEmpty(store.proxy().password())) {
                    logger.info(
                            "Setting proxy credentials (username: '{}', password: '***') for store '{}' flare client.",
                            store.proxy().username(), storeId);
                    builder.setProxyAuthenticationStrategy(new ProxyAuthenticationStrategy());
                    credentialsProvider.setCredentials(new AuthScope(proxy),
                            new UsernamePasswordCredentials(store.proxy().username(), store.proxy().password()));
                }
            }
            if (store.basicAuth() != null) {
                logger.info(
                        "Setting basic authentication (username: '{}', password: '***') for store '{}' flare client.",
                        store.basicAuth().username(), storeId);
                var flareUri = store.baseUrl().toURI();
                credentialsProvider.setCredentials(new AuthScope(new HttpHost(flareUri.getHost(), flareUri.getPort())),
                        new UsernamePasswordCredentials(store.basicAuth().username(), store.basicAuth().password()));
            } else if (store.bearerAuth() != null) {
                logger.info("Setting bearer token '***' for store '{}' flare client.", storeId);
                return new BearerHttpClient(builder.setDefaultCredentialsProvider(credentialsProvider).build(),
                        store.bearerAuth().token());
            } else if (store.oAuth() != null) {
                return new OAuthHttpClient(builder.setDefaultCredentialsProvider(credentialsProvider).build(),
                        store.oAuth().issuerUrl(), store.oAuth().clientId(), store.oAuth().clientPassword(),
                        DefaultTrustStoreUtils.loadTrustStore(trustedCACertificates), store.oAuth().proxy());
            }
            return builder.setDefaultCredentialsProvider(credentialsProvider).build();
        } catch (Exception e) {
            throw new IllegalArgumentException("Error creating flare client for store '%s'.".formatted(storeId), e);
        }
    }

    private final class BearerHttpClient extends CloseableHttpClient {
        private CloseableHttpClient client;
        private String token;

        public BearerHttpClient(CloseableHttpClient client, String token) {
            this.client = client;
            this.token = token;
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
        public void close() throws IOException {
            client.close();
        }

        @Override
        protected CloseableHttpResponse doExecute(HttpHost target, HttpRequest request, HttpContext context)
                throws IOException, ClientProtocolException {
            return client.execute(target, request, context);
        }

        @Override
        public <T> T execute(HttpUriRequest request, ResponseHandler<? extends T> responseHandler)
                throws IOException, ClientProtocolException {
            request.setHeader(new BasicHeader(HEADER_AUTHORIZATION,
                    HEADER_AUTHORIZATION_VALPREFIX_BEARER + token));
            return super.execute(request, responseHandler);
        }

    }

    private final class OAuthHttpClient extends CloseableHttpClient {

        private CloseableHttpClient client;
        private OAuthInterceptor interceptor;

        public OAuthHttpClient(CloseableHttpClient closeableHttpClient, URL issuerUrl, String clientId,
                String clientPassword, KeyStore trustStore, ProxySettings proxy)
                throws IOException, KeyStoreException, CertificateException, NoSuchAlgorithmException {
            client = closeableHttpClient;
            interceptor = new OAuthInterceptor(clientId, clientPassword, issuerUrl.toString(), trustStore,
                    Optional.ofNullable(proxy).map(p -> p.host()), Optional.ofNullable(proxy).map(p -> p.port()),
                    Optional.ofNullable(proxy).map(p -> p.username()),
                    Optional.ofNullable(proxy).map(p -> p.password()));
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
        public void close() throws IOException {
            client.close();
        }

        @Override
        protected CloseableHttpResponse doExecute(HttpHost target, HttpRequest request, HttpContext context)
                throws IOException, ClientProtocolException {
            return client.execute(target, interceptor.interceptRequest(request), context);
        }
    }
}
