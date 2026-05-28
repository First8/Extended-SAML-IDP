package nl.first8.keycloak.broker.saml;

import jakarta.ws.rs.core.Response;
import java.lang.reflect.Field;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.cert.CertificateException;
import java.util.stream.Stream;
import nl.first8.saml.util.SAMLUtil;
import org.bouncycastle.operator.OperatorCreationException;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.IdentityProvider;
import org.keycloak.common.ClientConnection;
import org.keycloak.common.enums.SslRequired;
import org.keycloak.forms.login.LoginFormsProvider;
import org.keycloak.models.KeyManager;
import org.keycloak.models.KeycloakContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.KeycloakTransactionManager;
import org.keycloak.models.KeycloakUriInfo;
import org.keycloak.models.RealmModel;
import org.keycloak.models.RealmProvider;
import org.keycloak.saml.validators.DestinationValidator;
import org.keycloak.services.messages.Messages;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.mockito.ArgumentCaptor;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.xmlsec.encryption.support.EncryptionException;
import org.opensaml.xmlsec.signature.support.SignatureException;

class SAMLEndpointTest {


    @Test
    public void testHandleSamlResponse() throws URISyntaxException, IllegalAccessException, MarshallingException, SignatureException, EncryptionException {
        KeycloakSession session = getMockKeycloakSession();
        SAMLIdentityProvider provider = getMockSamlIdentityProvider();
        SAMLIdentityProviderConfig config = getMockConfig();
        IdentityProvider.AuthenticationCallback callback = getMockAuthenticationCallback();
        DestinationValidator validator = getMockDestinationValidator();

        SAMLEndpoint endpoint = new SAMLEndpoint(session, provider, config, callback, validator);

        // clientConnection and session are @Context-injected in a real container; only the
        // success path reaches code that reads them, so only this test needs to inject them.
        boolean clientConnectionInjected = false;
        boolean sessionInjected = false;
        for (Field field : endpoint.getClass().getDeclaredFields()) {
            if (field.getName().equals("clientConnection")) {
                field.setAccessible(true);
                field.set(endpoint, getMockClientConnection());
                clientConnectionInjected = true;
            } else if (field.getName().equals("session")) {
                field.setAccessible(true);
                field.set(endpoint, session);
                sessionInjected = true;
            }
        }
        // These assertions are here in case the implementation ever changes
        assertTrue(clientConnectionInjected, "SAMLEndpoint no longer has a 'clientConnection' field - update this injection");
        assertTrue(sessionInjected, "SAMLEndpoint no longer has a 'session' field - update this injection");

        ArgumentCaptor<BrokeredIdentityContext> captor = ArgumentCaptor.forClass(BrokeredIdentityContext.class);

        Response response = endpoint.postBinding("", "", "samlArtifact", "relayState");
        assertEquals(Response.Status.Family.REDIRECTION, response.getStatusInfo().getFamily());

        verify(callback).authenticated(captor.capture());

        BrokeredIdentityContext identity = captor.getValue();
        assertEquals("9170bd139d9b5e364290187482329e89bcb431ea", identity.getId());
        assertEquals("test-alias.9170bd139d9b5e364290187482329e89bcb431ea", identity.getBrokerUserId());
        assertNotNull(identity.getContextData().get(SAMLEndpoint.SAML_ASSERTION));
        assertNotNull(identity.getContextData().get(SAMLEndpoint.SAML_LOGIN_RESPONSE));
    }

    @Test
    public void testHandleSamlResponse_expiredAssertion() throws URISyntaxException, MarshallingException, SignatureException, EncryptionException {
        KeycloakSession session = getMockKeycloakSession();
        LoginFormsProvider loginFormsProvider = session.getProvider(LoginFormsProvider.class);
        SAMLIdentityProvider provider = mock(SAMLIdentityProvider.class);
        String expiredArtifactResponse = SAMLUtil.createArtifactResponseWithExpiredAssertionAsString();
        when(provider.resolveArtifact(anyString(), anyString(), any(RealmModel.class))).thenReturn(expiredArtifactResponse);

        SAMLIdentityProviderConfig config = getMockConfig();
        IdentityProvider.AuthenticationCallback callback = getMockAuthenticationCallback();
        DestinationValidator validator = getMockDestinationValidator();

        SAMLEndpoint endpoint = new SAMLEndpoint(session, provider, config, callback, validator);

        Response response = endpoint.postBinding("", "", "samlArtifact", "relayState");
        assertEquals(Response.Status.Family.CLIENT_ERROR, response.getStatusInfo().getFamily());

        verify(callback, never()).authenticated(any(BrokeredIdentityContext.class));
        verify(loginFormsProvider).setError(eq(Messages.EXPIRED_CODE), any(Object[].class));
    }

    @Test
    public void testHandleSamlResponse_wrongSignature() throws URISyntaxException, MarshallingException, SignatureException, EncryptionException, OperatorCreationException, CertificateException {
        KeycloakSession session = getMockKeycloakSession();
        LoginFormsProvider loginFormsProvider = session.getProvider(LoginFormsProvider.class);
        SAMLIdentityProvider provider = mock(SAMLIdentityProvider.class);
        String wrongSigArtResponse = SAMLUtil.createArtifactResponseSignedWithWrongKeyAsString();
        when(provider.resolveArtifact(anyString(), anyString(), any(RealmModel.class))).thenReturn(wrongSigArtResponse);

        SAMLIdentityProviderConfig config = getMockConfigWithSignatureValidation();
        IdentityProvider.AuthenticationCallback callback = getMockAuthenticationCallback();
        DestinationValidator validator = getMockDestinationValidator();

        SAMLEndpoint endpoint = new SAMLEndpoint(session, provider, config, callback, validator);

        // The response is signed with a key that does not match the trusted cert in the config.
        // SAMLEndpoint.verifySignature() throws VerificationException, which is caught and
        // turned into a BAD_REQUEST error page with IDENTITY_PROVIDER_INVALID_SIGNATURE.
        Response response = endpoint.postBinding("", "", "samlArtifact", "relayState");
        assertEquals(Response.Status.Family.CLIENT_ERROR, response.getStatusInfo().getFamily());

        verify(callback, never()).authenticated(any(BrokeredIdentityContext.class));
        verify(loginFormsProvider).setError(eq(Messages.IDENTITY_PROVIDER_INVALID_SIGNATURE), any(Object[].class));
    }

    /**
     * Config variant that enables signature validation and supplies the correct public key.
     * Used by the wrong-signature test, where the response is signed with a *different* key,
     * so we need real validation to fire and produce IDENTITY_PROVIDER_INVALID_SIGNATURE.
     */
    private SAMLIdentityProviderConfig getMockConfigWithSignatureValidation() throws OperatorCreationException, CertificateException {
        SAMLIdentityProviderConfig config = mock(SAMLIdentityProviderConfig.class);
        when(config.getAlias()).thenReturn("test-alias");
        when(config.isValidateSignature()).thenReturn(true);
        when(config.getAllowedClockSkew()).thenReturn(15);
        when(config.getSigningCertificates()).thenReturn(new String[]{SAMLUtil.getCorrectPublicKeyCertificateAsBase64()});
        return config;
    }

    /**
     * Stubs the broker callback so SAMLEndpoint can complete without a real Keycloak flow.
     * Returns a redirect from authenticated() - used with ArgumentCaptor in the happy-path
     * test to assert on the BrokeredIdentityContext that was handed to Keycloak.
     */
    private IdentityProvider.AuthenticationCallback getMockAuthenticationCallback() {
        AuthenticationSessionModel authSession = mock(AuthenticationSessionModel.class);

        IdentityProvider.AuthenticationCallback callback = mock(IdentityProvider.AuthenticationCallback.class);
        when(callback.getAndVerifyAuthenticationSession(anyString())).thenReturn(authSession);
        Response redirectResponse = mock(Response.class);
        when(redirectResponse.getStatusInfo()).thenReturn(Response.Status.FOUND);
        when(callback.authenticated(any(BrokeredIdentityContext.class))).thenReturn(redirectResponse);
        return callback;
    }

    /**
     * String overload always passes - skips the ACS URL check (no real server URL in tests).
     * URI overload delegates to the real implementation so ConditionsValidator can still
     * perform its audience restriction check against the base URI from the session mock.
     */
    private DestinationValidator getMockDestinationValidator() {
        DestinationValidator validator = mock(DestinationValidator.class);
        when(validator.validate(anyString(), anyString())).thenReturn(true);
        // ConditionsValidator (called indirectly from SAMLEndpoint) uses the URI overload for audience checks
        when(validator.validate(any(URI.class), any(URI.class))).thenCallRealMethod();
        return validator;
    }

    /**
     * Provides a loopback address so SSL-required checks and remote-address logging don't
     * NPE. Injected both via the session context and directly into SAMLEndpoint via reflection
     * in the happy-path test (the only test that reaches the authenticated() code path).
     */
    private ClientConnection getMockClientConnection() {
        ClientConnection connection = mock(ClientConnection.class);
        when(connection.getRemoteAddr()).thenReturn("127.0.0.1");
        return connection;
    }

    /**
     * Minimal config with signature validation disabled (there's a different test for that: SamlSignatureValidationTest).
     * Used by tests that exercise parsing and session mapping but do not need to test cryptographic verification.
     */
    private SAMLIdentityProviderConfig getMockConfig() {
        SAMLIdentityProviderConfig config = mock(SAMLIdentityProviderConfig.class);
        when(config.getAlias()).thenReturn("test-alias");
        when(config.isValidateSignature()).thenReturn(false);
        when(config.getAllowedClockSkew()).thenReturn(15);
        return config;
    }

    /**
     * Stubs resolveArtifact to return a pre-built valid response, bypassing the actual
     * SOAP call to the IdP's artifact resolution service. Happy-path test only.
     */
    private SAMLIdentityProvider getMockSamlIdentityProvider() throws MarshallingException, SignatureException, EncryptionException {
        SAMLIdentityProvider provider = mock(SAMLIdentityProvider.class);
        String artifactResponse = SAMLUtil.createArtifactResponseAsString();
        // If you want to test an artifactResponse from a file, comment the line above and replace it by the line below, (a Response might also work)
        // String artifactResponse = getFileFromResourceAsString("artifactResponse/<the-artifact-response-you-want>");
        when(provider.resolveArtifact(anyString(), anyString(), any(RealmModel.class)))
                .thenReturn(artifactResponse);
        return provider;
    }

    /**
     * Realm is the root context for most Keycloak calls. isEnabled() is checked at entry;
     * getSslRequired() drives whether Keycloak rewrites the redirect to HTTPS.
     * Kept in its own method because getMockKeycloakSession() needs it for the context stub.
     */
    private RealmModel getMockRealmModel() {
        SslRequired sslRequired = mock(SslRequired.class);
        when(sslRequired.isRequired(any(ClientConnection.class))).thenReturn(false);

        RealmModel realm = mock(RealmModel.class);
        when(realm.getName()).thenReturn("test-realm");
        when(realm.getSslRequired()).thenReturn(sslRequired);
        when(realm.isEnabled()).thenReturn(true);
        return realm;
    }

    /**
     * Assembles the full Keycloak session graph. Notable stubs:
     * - sessionFactory / innerSession: Keycloak spawns a child session for certain operations
     * - LoginFormsProvider: used by failure tests to assert on the error message rendered;
     * returned via session.getProvider(LoginFormsProvider.class) so tests can verify it
     */
    private KeycloakSession getMockKeycloakSession() throws URISyntaxException {
        KeycloakUriInfo uriInfo = mock(KeycloakUriInfo.class);
        when(uriInfo.getBaseUri()).thenReturn(new URI("https://auth.testhost.lcl"));

        KeycloakContext context = mock(KeycloakContext.class);
        when(context.getUri()).thenReturn(uriInfo);

        KeyManager keyManager = mock(KeyManager.class);
        when(keyManager.getActiveRsaKey(any(RealmModel.class))).thenReturn(getActiveRsaKey());

        RealmModel realm = getMockRealmModel();
        ClientConnection connection = getMockClientConnection();
        when(context.getRealm()).thenReturn(realm);
        when(context.getConnection()).thenReturn(connection);

        KeycloakSessionFactory sessionFactory = mock(KeycloakSessionFactory.class);
        when(sessionFactory.getProviderFactoriesStream(any())).thenAnswer(inv -> Stream.empty());

        // Keycloak's runJobInTransaction calls sessionFactory.create() to open a fresh child session;
        // innerSession stubs that call so its transactionManager and realms() don't NPE.
        KeycloakSession innerSession = mock(KeycloakSession.class);
        KeycloakTransactionManager tm = mock(KeycloakTransactionManager.class);
        when(innerSession.getTransactionManager()).thenReturn(tm);
        RealmProvider realmProvider = mock(RealmProvider.class);
        when(innerSession.realms()).thenReturn(realmProvider);
        when(innerSession.getKeycloakSessionFactory()).thenReturn(sessionFactory);
        when(sessionFactory.create()).thenReturn(innerSession);

        LoginFormsProvider loginFormsProvider = mock(LoginFormsProvider.class);
        when(loginFormsProvider.setAuthenticationSession(any())).thenReturn(loginFormsProvider);
        when(loginFormsProvider.setError(anyString())).thenReturn(loginFormsProvider);
        when(loginFormsProvider.setError(anyString(), any(Object[].class))).thenReturn(loginFormsProvider);
        Response errorResponse = mock(Response.class);
        when(errorResponse.getStatusInfo()).thenReturn(Response.Status.BAD_REQUEST);
        when(loginFormsProvider.createErrorPage(any(Response.Status.class))).thenReturn(errorResponse);

        KeycloakSession session = mock(KeycloakSession.class);
        when(session.getContext()).thenReturn(context);
        when(session.keys()).thenReturn(keyManager);
        when(session.getKeycloakSessionFactory()).thenReturn(sessionFactory);
        when(session.getProvider(LoginFormsProvider.class)).thenReturn(loginFormsProvider);
        return session;
    }

    /**
     * Wraps the shared TEST_KEY_PAIR as Keycloak's ActiveRsaKey. The same key is used by
     * SAMLUtil to sign the test SAML responses, so end-to-end signature round-trips work.
     */
    private KeyManager.ActiveRsaKey getActiveRsaKey() {
        return new KeyManager.ActiveRsaKey("kid", SAMLUtil.TEST_KEY_PAIR.getPrivate(), SAMLUtil.TEST_KEY_PAIR.getPublic(), null);
    }
}
