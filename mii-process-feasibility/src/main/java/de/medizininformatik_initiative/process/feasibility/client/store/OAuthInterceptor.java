package de.medizininformatik_initiative.process.feasibility.client.store;

import ca.uhn.fhir.rest.api.Constants;
import ca.uhn.fhir.rest.client.api.IClientInterceptor;
import ca.uhn.fhir.rest.client.api.IHttpRequest;
import ca.uhn.fhir.rest.client.api.IHttpResponse;
import com.nimbusds.oauth2.sdk.AccessTokenResponse;
import com.nimbusds.oauth2.sdk.ClientCredentialsGrant;
import com.nimbusds.oauth2.sdk.GeneralException;
import com.nimbusds.oauth2.sdk.TokenErrorResponse;
import com.nimbusds.oauth2.sdk.TokenRequest;
import com.nimbusds.oauth2.sdk.TokenResponse;
import com.nimbusds.oauth2.sdk.auth.ClientSecretBasic;
import com.nimbusds.oauth2.sdk.auth.Secret;
import com.nimbusds.oauth2.sdk.http.HTTPRequest;
import com.nimbusds.oauth2.sdk.id.ClientID;
import com.nimbusds.oauth2.sdk.id.Issuer;
import com.nimbusds.oauth2.sdk.token.AccessToken;
import com.nimbusds.oauth2.sdk.util.tls.TLSUtils;
import com.nimbusds.openid.connect.sdk.op.OIDCProviderMetadata;
import org.apache.http.HttpRequest;
import org.joda.time.DateTime;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Proxy.Type;
import java.net.URI;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.util.Base64;
import java.util.Optional;

public final class OAuthInterceptor implements IClientInterceptor {

    private static final String HEADER_PROXY_AUTHORIZATION = "Proxy-Authorization";
    private static final int TOKEN_EXPIRY_THRESHOLD = 10000;
    private HTTPRequest tokenRequest;
    private AccessToken token;
    private DateTime tokenExpiry;
    private Optional<Proxy> proxy;
    private Optional<String> proxyAuthHeader;
    private Issuer issuer;
    private ClientSecretBasic clientAuth;
    private KeyStore trustStore;

    public OAuthInterceptor(String oauthClientId, String oauthClientSecret, String oauthIssuerUrl,
            KeyStore trustStore, Optional<String> proxyHost, Optional<Integer> proxyPort,
            Optional<String> proxyUsername, Optional<String> proxyPassword) {
        super();
        this.trustStore = trustStore;
        clientAuth = new ClientSecretBasic(new ClientID(oauthClientId), new Secret(oauthClientSecret));
        issuer = new Issuer(oauthIssuerUrl);
        proxy = proxyHost.map(
                h -> proxyPort.map(
                        p -> new Proxy(Type.HTTP, InetSocketAddress.createUnresolved(h, p))).orElse(null));
        proxyAuthHeader = proxyUsername.map(
                n -> proxyPassword.map(
                        p -> generateBasicAuthHeader(n, p)).orElse(null));
    }

    private String generateBasicAuthHeader(String username, String password) {
        return Constants.HEADER_AUTHORIZATION_VALPREFIX_BASIC
                + Base64.getEncoder().encodeToString((username + ":" + password).getBytes(Constants.CHARSET_US_ASCII));
    }

    public String getToken() {
        if (token == null || tokenExpiry == null || tokenExpiry.isBefore(DateTime.now().plus(TOKEN_EXPIRY_THRESHOLD))) {
            try {
                TokenResponse response = TokenResponse.parse(getTokenRequest().send());
                if (!response.indicatesSuccess()) {
                    TokenErrorResponse errorResponse = response.toErrorResponse();
                    throw new OAuth2ClientException(errorResponse.getErrorObject().getCode() + " - "
                            + errorResponse.getErrorObject().getDescription());
                }
                AccessTokenResponse successResponse = response.toSuccessResponse();

                token = successResponse.getTokens().getAccessToken();
                tokenExpiry = DateTime.now().plus(token.getLifetime() * 1000);
            } catch (Exception e) {
                throw new OAuth2ClientException("Requesting OAuth2 access token failed: " + e.getMessage(), e);
            }
        }
        return token.getValue();
    }

    private HTTPRequest getTokenRequest() throws GeneralException, IOException, KeyManagementException,
            UnrecoverableKeyException, NoSuchAlgorithmException, KeyStoreException {
        if (tokenRequest == null) {
            HTTPRequest request = new TokenRequest(getTokenUri(), clientAuth, new ClientCredentialsGrant())
                    .toHTTPRequest();
            tokenRequest = setProxy(setSSLSocketFactory(request));
        }
        return tokenRequest;
    }

    private URI getTokenUri() throws GeneralException, IOException {
        return OIDCProviderMetadata.resolve(issuer, r -> setProxy(setSSLSocketFactory(r))).getTokenEndpointURI();
    }

    private HTTPRequest setSSLSocketFactory(HTTPRequest request) {
        try {
            request.setSSLSocketFactory(TLSUtils.createSSLSocketFactory(trustStore));
        } catch (KeyManagementException | UnrecoverableKeyException | NoSuchAlgorithmException | KeyStoreException e) {
            throw new IllegalArgumentException("Could not configure TLS with given trust store.", e);
        }
        return request;
    }

    private HTTPRequest setProxy(HTTPRequest request) {
        if (proxy.isPresent()) {
            request.setProxy(proxy.get());
            if (proxyAuthHeader.isPresent()) {
               request.setHeader(HEADER_PROXY_AUTHORIZATION, proxyAuthHeader.get());
            }
        }
        return request;
    }

    @Override
    public void interceptRequest(IHttpRequest theRequest) {
        theRequest.addHeader(Constants.HEADER_AUTHORIZATION,
                Constants.HEADER_AUTHORIZATION_VALPREFIX_BEARER + getToken());
    }

    public HttpRequest interceptRequest(HttpRequest request) {
        request.addHeader(Constants.HEADER_AUTHORIZATION,
                Constants.HEADER_AUTHORIZATION_VALPREFIX_BEARER + getToken());
        return request;
    }

    @Override
    public void interceptResponse(IHttpResponse theResponse) throws IOException {
    }
}
