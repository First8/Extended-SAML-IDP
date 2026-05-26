package nl.first8.keycloak.broker.saml;

import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityProvider;
import org.keycloak.broker.provider.UserAuthenticationIdentityProvider;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.sessions.AuthenticationSessionModel;

import java.net.URI;
import java.net.URISyntaxException;

/**
 * Wraps an {@link UserAuthenticationIdentityProvider.AuthenticationCallback} to intercept error responses
 * and redirect the user to a configurable client-side callback path instead of showing the default Keycloak error page.
 */
public class ErrorRedirectCallbackWrapper implements UserAuthenticationIdentityProvider.AuthenticationCallback {

    private static final Logger logger = Logger.getLogger(ErrorRedirectCallbackWrapper.class);

    private final KeycloakSession session;
    private final SAMLIdentityProviderConfig config;
    private final UserAuthenticationIdentityProvider.AuthenticationCallback delegate;

    public ErrorRedirectCallbackWrapper(KeycloakSession session,
                                        SAMLIdentityProviderConfig config,
                                        UserAuthenticationIdentityProvider.AuthenticationCallback delegate) {
        this.session = session;
        this.config = config;
        this.delegate = delegate;
    }

    @Override
    public Response authenticated(BrokeredIdentityContext context) {
        return delegate.authenticated(context);
    }

    @Override
    public Response cancelled(IdentityProviderModel idpConfig) {
        Response redirect = buildRedirectResponse(config.getCancelledCallbackPath());
        if (redirect != null) {
            return redirect;
        }
        return delegate.cancelled(idpConfig);
    }

    @Override
    public Response error(IdentityProviderModel idpConfig, String message) {
        logger.warnf("Error callback intercepted with message: %s", message);

        String callbackPath = determineCallbackPath(message);
        Response redirect = buildRedirectResponse(callbackPath);
        if (redirect != null) {
            return redirect;
        }

        logger.warn("Could not determine callback URL, falling back to default error handling");
        return delegate.error(idpConfig, message);
    }

    @Override
    public AuthenticationSessionModel getAndVerifyAuthenticationSession(String encodedCode) {
        return delegate.getAndVerifyAuthenticationSession(encodedCode);
    }

    @Override
    public Response retryLogin(UserAuthenticationIdentityProvider<?> identityProvider, AuthenticationSessionModel authSession) {
        return delegate.retryLogin(identityProvider, authSession);
    }

    String determineCallbackPath(String message) {
        if (message != null) {
            if (message.contains("RequestDenied") || message.contains("denied") || message.contains("Denied")) {
                return config.getErrorCallbackPath();
            }
        }
        // Default: treat as cancelled (AuthnFailed, cancelled, or unknown)
        return config.getCancelledCallbackPath();
    }

    private Response buildRedirectResponse(String callbackPath) {
        AuthenticationSessionModel authSession = session.getContext().getAuthenticationSession();
        if (authSession == null) {
            logger.warn("No authentication session available for error redirect");
            return null;
        }

        String callbackUrl = buildCallbackUrl(authSession.getRedirectUri(), callbackPath);
        if (callbackUrl == null) {
            callbackUrl = buildCallbackUrl(authSession.getClient().getBaseUrl(), callbackPath);
        }

        if (callbackUrl != null) {
            logger.infof("Redirecting to: %s", callbackUrl);
            return Response.status(Response.Status.FOUND).location(URI.create(callbackUrl)).build();
        }

        return null;
    }

    /**
     * Builds a callback URL by extracting scheme, host, and port from the source URL
     * and appending the configured callback path.
     * Returns null if the source URL is invalid or blank.
     */
    static String buildCallbackUrl(String sourceUrl, String callbackPath) {
        if (sourceUrl == null || sourceUrl.isBlank()) {
            return null;
        }

        try {
            URI uri = new URI(sourceUrl);
            String scheme = uri.getScheme();
            String host = uri.getHost();

            if (scheme == null || host == null) {
                return null;
            }

            // Only allow https (or http for localhost development)
            if (!"https".equalsIgnoreCase(scheme) && !"http".equalsIgnoreCase(scheme)) {
                logger.warnf("Rejected redirect with unsupported scheme: %s", scheme);
                return null;
            }

            // Sanitize callbackPath: must start with / and not contain query/fragment or path traversal
            if (callbackPath == null || !callbackPath.startsWith("/")
                    || callbackPath.contains("..") || callbackPath.contains("?")
                    || callbackPath.contains("#") || callbackPath.contains("//")) {
                logger.warnf("Rejected invalid callback path: %s", callbackPath);
                return null;
            }

            StringBuilder sb = new StringBuilder();
            sb.append(scheme).append("://").append(host);
            if (uri.getPort() > 0 && uri.getPort() != 443 && uri.getPort() != 80) {
                sb.append(":").append(uri.getPort());
            }
            sb.append(callbackPath);

            return sb.toString();
        } catch (URISyntaxException e) {
            logger.warnf("Failed to parse source URL for error redirect: %s", e.getMessage());
            return null;
        }
    }
}
