package nl.first8.keycloak.broker.saml;

import nl.first8.keycloak.dom.saml.v2.assertion.AssertionType;
import nl.first8.keycloak.dom.saml.v2.metadata.AttributeConsumingServiceType;
import nl.first8.keycloak.dom.saml.v2.metadata.EntityDescriptorType;
import nl.first8.keycloak.protocol.saml.JaxrsSAML2BindingBuilder;
import nl.first8.keycloak.saml.SAML2ArtifactResolutionBuilder;
import nl.first8.keycloak.saml.SAML2AuthnRequestBuilder;
import nl.first8.keycloak.saml.SPMetadataDescriptorBuilder;
import nl.first8.keycloak.saml.common.constants.GeneralConstants;
import nl.first8.keycloak.saml.processing.api.saml.v2.request.SAML2Request;
import nl.first8.keycloak.saml.processing.core.saml.v2.writers.SAMLMetadataWriter;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.*;
import org.keycloak.broker.provider.util.SimpleHttp;
import org.keycloak.common.util.PemUtils;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyStatus;
import org.keycloak.crypto.KeyUse;
import org.keycloak.dom.saml.v2.assertion.AuthnStatementType;
import org.keycloak.dom.saml.v2.assertion.NameIDType;
import org.keycloak.dom.saml.v2.assertion.SubjectType;
import org.keycloak.dom.saml.v2.metadata.LocalizedNameType;
import org.keycloak.dom.saml.v2.metadata.RequestedAttributeType;
import org.keycloak.dom.saml.v2.protocol.*;
import org.keycloak.events.EventBuilder;
import org.keycloak.models.*;
import org.keycloak.protocol.oidc.OIDCLoginProtocol;
import org.keycloak.protocol.saml.SamlProtocol;
import org.keycloak.protocol.saml.SamlService;
import org.keycloak.protocol.saml.SamlSessionUtils;
import org.keycloak.protocol.saml.preprocessor.SamlAuthenticationPreprocessor;
import org.keycloak.saml.*;
import org.keycloak.saml.SamlProtocolExtensionsAwareBuilder.NodeGenerator;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;
import org.keycloak.saml.common.exceptions.ConfigurationException;
import org.keycloak.saml.common.exceptions.ProcessingException;
import org.keycloak.saml.common.util.DocumentUtil;
import org.keycloak.saml.common.util.StaxUtil;
import org.keycloak.saml.processing.api.saml.v2.sig.SAML2Signature;
import org.keycloak.saml.processing.core.util.KeycloakKeySamlExtensionGenerator;
import org.keycloak.saml.validators.DestinationValidator;
import org.keycloak.sessions.AuthenticationSessionModel;
import org.keycloak.util.JsonSerialization;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.UriBuilder;
import javax.ws.rs.core.UriInfo;
import javax.xml.crypto.dsig.CanonicalizationMethod;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.stream.XMLStreamWriter;
import java.io.IOException;
import java.io.StringWriter;
import java.net.URI;
import java.net.URISyntaxException;
import java.security.KeyPair;
import java.util.*;

import static org.keycloak.saml.common.constants.JBossSAMLURIConstants.ATTRIBUTE_FORMAT_BASIC;

public class SAMLIdentityProvider extends AbstractIdentityProvider<SAMLIdentityProviderConfig> {
    protected static final Logger logger = Logger.getLogger(SAMLIdentityProvider.class);

    private final DestinationValidator destinationValidator;

    public SAMLIdentityProvider(KeycloakSession session, SAMLIdentityProviderConfig config, DestinationValidator destinationValidator) {
        super(session, config);
        this.destinationValidator = destinationValidator;
    }

    @Override
    public Object callback(RealmModel realm, AuthenticationCallback callback, EventBuilder event) {
        return new SAMLEndpoint(realm, this, getConfig(), callback, destinationValidator);
    }

    @Override
    public Response performLogin(AuthenticationRequest request) {
        try {
            UriInfo uriInfo = request.getUriInfo();
            RealmModel realm = request.getRealm();
            String issuerURL = getEntityId(uriInfo, realm);
            String destinationUrl = getConfig().getSingleSignOnServiceUrl();
            String nameIDPolicyFormat = getConfig().getNameIDPolicyFormat();

            if (nameIDPolicyFormat == null) {
                nameIDPolicyFormat =  JBossSAMLURIConstants.NAMEID_FORMAT_PERSISTENT.get();
            }

            String protocolBinding = JBossSAMLURIConstants.SAML_HTTP_REDIRECT_BINDING.get();

            String assertionConsumerServiceUrl = request.getRedirectUri();

            if (getConfig().isPostBindingResponse()) {
                protocolBinding = JBossSAMLURIConstants.SAML_HTTP_POST_BINDING.get();
            }

            SAML2RequestedAuthnContextBuilder requestedAuthnContext =
                new SAML2RequestedAuthnContextBuilder()
                    .setComparison(getConfig().getAuthnContextComparisonType());

            for (String authnContextClassRef : getAuthnContextClassRefUris())
                requestedAuthnContext.addAuthnContextClassRef(authnContextClassRef);

            for (String authnContextDeclRef : getAuthnContextDeclRefUris())
                requestedAuthnContext.addAuthnContextDeclRef(authnContextDeclRef);

            String loginHint = getConfig().isLoginHint() ? request.getAuthenticationSession().getClientNote(OIDCLoginProtocol.LOGIN_HINT_PARAM) : null;
            Boolean allowCreate = null;
            if (getConfig().getConfig().get(SAMLIdentityProviderConfig.ALLOW_CREATE) == null || getConfig().isAllowCreate())
                allowCreate = Boolean.TRUE;
            SAML2AuthnRequestBuilder authnRequestBuilder = new SAML2AuthnRequestBuilder()
                    .destination(destinationUrl)
                    .issuer(issuerURL)
                    .forceAuthn(getConfig().isForceAuthn())
                    .protocolBinding(protocolBinding)
                    .nameIdPolicy(SAML2NameIDPolicyBuilder
                        .format(nameIDPolicyFormat)
                        .setAllowCreate(allowCreate))
                    .requestedAuthnContext(requestedAuthnContext)
                    .subject(loginHint);
            Integer assertionConsumingServiceIndex = getConfig().getAssertionConsumingServiceIndex();
            if(assertionConsumingServiceIndex != null) {
                authnRequestBuilder.assertionConsumerIndex(assertionConsumingServiceIndex);
            } else {
                authnRequestBuilder.assertionConsumerUrl(assertionConsumerServiceUrl);
            }
            Integer attributeConsumingServiceIndex = getConfig().getAttributeConsumingServiceIndex();
            if(attributeConsumingServiceIndex != null)
                authnRequestBuilder.attributeConsumingServiceIndex(attributeConsumingServiceIndex);

            List<String> scoping = getScoping();
            if(scoping != null && !scoping.isEmpty()) {
                logger.debugf("Adding scoping to AuthNRequest: %s", scoping);
                IDPListType idpListType = new IDPListType();
                scoping.stream()
                        .filter(entry -> !entry.isEmpty())
                        .forEach(entry -> {
                            try {
                                IDPEntryType idpEntryType = new IDPEntryType();
                                idpEntryType.setProviderID(new URI(entry));
                                idpListType.addIDPEntry(idpEntryType);
                            } catch (URISyntaxException e) {
                                logger.warnf("Scope %s not added as not valid URI. Ignoring this entry.", entry);
                            }
                        });
                ScopingType scopingType = new ScopingType();
                scopingType.setIDPList(idpListType);
                authnRequestBuilder.scoping(scopingType);
            }

            JaxrsSAML2BindingBuilder binding = new JaxrsSAML2BindingBuilder(session, getConfig())
                    .relayState(request.getState().getEncoded());
            boolean postBinding = getConfig().isPostBindingAuthnRequest();

            logger.debugf("Use %s for AuthNRequest", (postBinding?"PostBinding":"RedirectBinding"));
            logger.debugf("AuthNRequest should be signed: %b", getConfig().isWantAuthnRequestsSigned());
            if (getConfig().isWantAuthnRequestsSigned()) {
                KeyManager.ActiveRsaKey keys = session.keys().getActiveRsaKey(realm);

                String keyName = getConfig().getXmlSigKeyInfoKeyNameTransformer().getKeyName(keys.getKid(), keys.getCertificate());
                logger.debugf("Signing using key: %s", keyName);
                binding.signWith(keyName, keys.getPrivateKey(), keys.getPublicKey(), keys.getCertificate())
                        .signatureAlgorithm(getSignatureAlgorithm())
                        .signDocument();
                if (! postBinding && getConfig().isAddExtensionsElementWithKeyInfo()) {    // Only include extension if REDIRECT binding and signing whole SAML protocol message
                    authnRequestBuilder.addExtension(new KeycloakKeySamlExtensionGenerator(keyName));
                }
            }

            AuthnRequestType authnRequest = authnRequestBuilder.createAuthnRequest();
            for(Iterator<SamlAuthenticationPreprocessor> it = SamlSessionUtils.getSamlAuthenticationPreprocessorIterator(session); it.hasNext(); ) {
                authnRequest = it.next().beforeSendingLoginRequest(authnRequest, request.getAuthenticationSession());
            }

            if (authnRequest.getDestination() != null) {
                destinationUrl = authnRequest.getDestination().toString();
            }

            // Save the current RequestID in the Auth Session as we need to verify it against the ID returned from the IdP
            request.getAuthenticationSession().setClientNote(SamlProtocol.SAML_REQUEST_ID_BROKER, authnRequest.getID());


            Document authnRequestDocument = authnRequestBuilder.toDocument();
            if(logger.isTraceEnabled()) {
                logger.tracef("AuthNRequest document: %s", DocumentUtil.getDocumentAsString(authnRequestDocument));
            }
            if (postBinding) {
                return binding.postBinding(authnRequestDocument).request(destinationUrl);
            } else {
                return binding.redirectBinding(authnRequestDocument).request(destinationUrl);
            }
        } catch (Exception e) {
            throw new IdentityBrokerException("Could not create authentication request.", e);
        }
    }

    private String getEntityId(UriInfo uriInfo, RealmModel realm) {
        String configEntityId = getConfig().getEntityId();

        if (configEntityId == null || configEntityId.isEmpty())
            return UriBuilder.fromUri(uriInfo.getBaseUri()).path("realms").path(realm.getName()).build().toString();
        else
            return configEntityId;
    }

    private List<String> getAuthnContextClassRefUris() {
        String authnContextClassRefs = getConfig().getAuthnContextClassRefs();
        if (authnContextClassRefs == null || authnContextClassRefs.isEmpty())
            return new LinkedList<String>();

        try {
            return Arrays.asList(JsonSerialization.readValue(authnContextClassRefs, String[].class));
        } catch (Exception e) {
            logger.warn("Could not json-deserialize AuthContextClassRefs config entry: " + authnContextClassRefs, e);
            return new LinkedList<String>();
        }
    }

    private List<String> getAuthnContextDeclRefUris() {
        String authnContextDeclRefs = getConfig().getAuthnContextDeclRefs();
        if (authnContextDeclRefs == null || authnContextDeclRefs.isEmpty())
            return new LinkedList<String>();

        try {
            return Arrays.asList(JsonSerialization.readValue(authnContextDeclRefs, String[].class));
        } catch (Exception e) {
            logger.warn("Could not json-deserialize AuthContextDeclRefs config entry: " + authnContextDeclRefs, e);
            return new LinkedList<String>();
        }
    }

    private List<String> getScoping() {
        String scoping = getConfig().getScoping();
        if (scoping == null || scoping.isEmpty())
            return new LinkedList<>();

        try {
            return Arrays.asList(scoping);
        } catch (Exception e) {
            logger.warn("Could not json-deserialize Scoping config entry: " + scoping, e);
            return new LinkedList<String>();
        }
    }

    @Override
    public void authenticationFinished(AuthenticationSessionModel authSession, BrokeredIdentityContext context)  {
        AssertionType assertion = (AssertionType)context.getContextData().get(SAMLEndpoint.SAML_ASSERTION);
        SubjectType subject = assertion.getSubject();
        SubjectType.STSubType subType = subject.getSubType();
        if (subType != null) {
            NameIDType subjectNameID = (NameIDType) subType.getBaseID();
            logger.debugf("Set User Session Notes with Subject Name ID: %s", subjectNameID);
            authSession.setUserSessionNote(SAMLEndpoint.SAML_FEDERATED_SUBJECT_NAMEID, subjectNameID.serializeAsString());
        }
        AuthnStatementType authn =  (AuthnStatementType)context.getContextData().get(SAMLEndpoint.SAML_AUTHN_STATEMENT);
        if (authn != null && authn.getSessionIndex() != null) {
            authSession.setUserSessionNote(SAMLEndpoint.SAML_FEDERATED_SESSION_INDEX, authn.getSessionIndex());

        }
    }

    @Override
    public Response retrieveToken(KeycloakSession session, FederatedIdentityModel identity) {
        return Response.ok(identity.getToken()).build();
    }

    @Override
    public void backchannelLogout(KeycloakSession session, UserSessionModel userSession, UriInfo uriInfo, RealmModel realm) {
        String singleLogoutServiceUrl = getConfig().getSingleLogoutServiceUrl();
        if (singleLogoutServiceUrl == null || singleLogoutServiceUrl.trim().equals("") || !getConfig().isBackchannelSupported()) return;
        JaxrsSAML2BindingBuilder binding = buildLogoutBinding(session, userSession, realm);
        try {
            LogoutRequestType logoutRequest = buildLogoutRequest(userSession, uriInfo, realm, singleLogoutServiceUrl);
            if (logoutRequest.getDestination() != null) {
                singleLogoutServiceUrl = logoutRequest.getDestination().toString();
            }
            int status = SimpleHttp.doPost(singleLogoutServiceUrl, session)
                    .param(GeneralConstants.SAML_REQUEST_KEY, binding.postBinding(SAML2Request.convert(logoutRequest)).encoded())
                    .param(GeneralConstants.RELAY_STATE, userSession.getId()).asStatus();
            boolean success = status >=200 && status < 400;
            if (!success) {
                logger.warn("Failed saml backchannel broker logout to: " + singleLogoutServiceUrl);
            }
        } catch (Exception e) {
            logger.warn("Failed saml backchannel broker logout to: " + singleLogoutServiceUrl, e);
        }

    }

    @Override
    public Response keycloakInitiatedBrowserLogout(KeycloakSession session, UserSessionModel userSession, UriInfo uriInfo, RealmModel realm) {
        String singleLogoutServiceUrl = getConfig().getSingleLogoutServiceUrl();
        if (singleLogoutServiceUrl == null || singleLogoutServiceUrl.trim().equals("")) return null;

        if (getConfig().isBackchannelSupported()) {
            backchannelLogout(session, userSession, uriInfo, realm);
            return null;
       } else {
            try {
                LogoutRequestType logoutRequest = buildLogoutRequest(userSession, uriInfo, realm, singleLogoutServiceUrl);
                if (logoutRequest.getDestination() != null) {
                    singleLogoutServiceUrl = logoutRequest.getDestination().toString();
                }
                JaxrsSAML2BindingBuilder binding = buildLogoutBinding(session, userSession, realm);
                if (getConfig().isPostBindingLogout()) {
                    return binding.postBinding(SAML2Request.convert(logoutRequest)).request(singleLogoutServiceUrl);
                } else {
                    return binding.redirectBinding(SAML2Request.convert(logoutRequest)).request(singleLogoutServiceUrl);
                }
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }
    }

    protected LogoutRequestType buildLogoutRequest(UserSessionModel userSession,
                                                   UriInfo uriInfo,
                                                   RealmModel realm,
                                                   String singleLogoutServiceUrl,
                                                   NodeGenerator... extensions) throws ConfigurationException {
        SAML2LogoutRequestBuilder logoutBuilder = new SAML2LogoutRequestBuilder()
                .assertionExpiration(realm.getAccessCodeLifespan())
                .issuer(getEntityId(uriInfo, realm))
                .sessionIndex(userSession.getNote(SAMLEndpoint.SAML_FEDERATED_SESSION_INDEX))
                .nameId(NameIDType.deserializeFromString(userSession.getNote(SAMLEndpoint.SAML_FEDERATED_SUBJECT_NAMEID)))
                .destination(singleLogoutServiceUrl);
        LogoutRequestType logoutRequest = logoutBuilder.createLogoutRequest();
        for (NodeGenerator extension : extensions) {
            logoutBuilder.addExtension(extension);
        }
        for (Iterator<SamlAuthenticationPreprocessor> it = SamlSessionUtils.getSamlAuthenticationPreprocessorIterator(session); it.hasNext();) {
            logoutRequest = it.next().beforeSendingLogoutRequest(logoutRequest, userSession, null);
        }
        return logoutRequest;
    }

    private JaxrsSAML2BindingBuilder buildLogoutBinding(KeycloakSession session, UserSessionModel userSession, RealmModel realm) {
        JaxrsSAML2BindingBuilder binding = new JaxrsSAML2BindingBuilder(session, getConfig())
                .relayState(userSession.getId());
        if (getConfig().isWantAuthnRequestsSigned()) {
            KeyManager.ActiveRsaKey keys = session.keys().getActiveRsaKey(realm);
            String keyName = getConfig().getXmlSigKeyInfoKeyNameTransformer().getKeyName(keys.getKid(), keys.getCertificate());
            binding.signWith(keyName, keys.getPrivateKey(), keys.getPublicKey(), keys.getCertificate())
                    .signatureAlgorithm(getSignatureAlgorithm())
                    .signDocument();
        }
        return binding;
    }

    public String resolveArtifact(String artifact, String issuerURL, RealmModel realm) {
        logger.debugf("Resolving artifact %s, from issuerURL %s, within realm %s", artifact, issuerURL, realm.getName());

        String response = "";
        try {
            SAML2ArtifactResolutionBuilder builder = new SAML2ArtifactResolutionBuilder()
                    .artifact(artifact)
                    .issuer(issuerURL);

            JaxrsSAML2BindingBuilder binding = new JaxrsSAML2BindingBuilder(session, getConfig());
            logger.debugf("Sign ArtifactResolve request? -> %s", getConfig().isSignArtifactResolutionRequest());
            if (getConfig().isSignArtifactResolutionRequest()) {
                KeyManager.ActiveRsaKey keys = session.keys().getActiveRsaKey(realm);

                KeyPair keypair = new KeyPair(keys.getPublicKey(), keys.getPrivateKey());

                String keyName = getConfig().getXmlSigKeyInfoKeyNameTransformer().getKeyName(keys.getKid(), keys.getCertificate());
                logger.debugf("Signing Artifact Resolve Message with key: %s", keyName);
                binding.signWith(keyName, keypair);
                binding.signatureAlgorithm(getSignatureAlgorithm());
                binding.signDocument();
            }

            URI artifactResolutionEndpoint = new URI(getConfig().getArtifactResolutionEndpoint());
            logger.debugf("Sending artifact resolve message to: %s", artifactResolutionEndpoint);
            response = binding.postBinding(builder.toDocument()).artifactResolutionRequest(artifactResolutionEndpoint, realm);
        } catch (ProcessingException | IOException | URISyntaxException e) {
            logger.warn("Cannot resolve SAMLArtifact returning empty response");
            logger.warn(e.getMessage(), e);
        }

        return response;
    }

    @Override
    public Response export(UriInfo uriInfo, RealmModel realm, String format) {
        logger.info("Exporting SAML v2.0 - Extended");
        try
        {
            URI authnBinding = JBossSAMLURIConstants.SAML_HTTP_REDIRECT_BINDING.getUri();
            if (getConfig().isPostBindingAuthnRequest()) {
                authnBinding = JBossSAMLURIConstants.SAML_HTTP_POST_BINDING.getUri();
            }

            URI artifactBinding = JBossSAMLURIConstants.SAML_SOAP_BINDING.getUri();

            List<URI> endpoints = new ArrayList();
            endpoints.add(uriInfo.getBaseUriBuilder()
                    .path("realms").path(realm.getName())
                    .path("broker")
                    .path(getConfig().getAlias())
                    .path("endpoint")
                    .build());
            List<String> linkedProviders = getConfig().getLinkedProviders();
            logger.debugf("Found %d number of linked providers.", linkedProviders.size());
            if(!linkedProviders.isEmpty()) {
                for(String linkedProvider : linkedProviders) {
                    endpoints.add(uriInfo.getBaseUriBuilder()
                            .path("realms").path(realm.getName())
                            .path("broker")
                            .path(linkedProvider)
                            .path("endpoint")
                            .build());
                }
            }

            URI artifactEndpoint = uriInfo.getBaseUriBuilder()
                    .path("realms").path(realm.getName())
                    .path("broker")
                    .path(getConfig().getAlias())
                    .path("endpoint")
                    .build();

            boolean wantAuthnRequestsSigned = getConfig().isWantAuthnRequestsSigned();
            boolean wantAssertionsSigned = getConfig().isWantAssertionsSigned();
            boolean wantAssertionsEncrypted = getConfig().isWantAssertionsEncrypted();
            String entityId = getEntityId(uriInfo, realm);
            String nameIDPolicyFormat = getConfig().getNameIDPolicyFormat();


            List<Element> signingKeys = new LinkedList<>();
            List<Element> encryptionKeys = new LinkedList<>();

            session.keys().getKeysStream(realm, KeyUse.SIG, Algorithm.RS256)
                    .filter(Objects::nonNull)
                    .filter(key -> key.getCertificate() != null)
                    .sorted(SamlService::compareKeys)
                    .forEach(key -> {
                        try {
                            Element element = SPMetadataDescriptor
                                    .buildKeyInfoElement(key.getKid(), PemUtils.encodeCertificate(key.getCertificate()));
                            signingKeys.add(element);

                            if (key.getStatus() == KeyStatus.ACTIVE) {
                                encryptionKeys.add(element);
                            }
                        } catch (ParserConfigurationException e) {
                            logger.warn("Failed to export SAML SP Metadata!", e);
                            throw new RuntimeException(e);
                        }
                    });

            // Prepare the metadata descriptor model
            StringWriter sw = new StringWriter();
            XMLStreamWriter writer = StaxUtil.getXMLStreamWriter(sw);
            SAMLMetadataWriter metadataWriter = new SAMLMetadataWriter(writer);

            Integer defaultAssertionEndpointIndex = getConfig().getAssertionConsumingServiceIndex();
            if(defaultAssertionEndpointIndex == null) {
                defaultAssertionEndpointIndex = 1;
            }

            SPMetadataDescriptorBuilder spMetadataDescriptorBuilder = new SPMetadataDescriptorBuilder()
                .loginBinding(authnBinding)
                    .logoutBinding(authnBinding)
                    .assertionEndpoints(endpoints)
                    .defaultAssertionEndpoint(defaultAssertionEndpointIndex)
                    .logoutEndpoints(endpoints)
                .wantAuthnRequestsSigned(wantAuthnRequestsSigned)
                    .wantAssertionsSigned(wantAssertionsSigned)
                    .wantAssertionsEncrypted(wantAssertionsEncrypted)
                .entityId(entityId)
                    .nameIDPolicyFormat(nameIDPolicyFormat)
                    .signingCerts(signingKeys)
                    .encryptionCerts(encryptionKeys);
            if(getConfig().isIncludeArtifactResolutionServiceMetadata()) {
                spMetadataDescriptorBuilder.artifactResolutionBinding(artifactBinding)
                        .artifactResolutionEndpoint(artifactEndpoint);
            }
            if(getConfig().getMetadataValidUntilUnit() != null && getConfig().getMetadataValidUntilPeriod() != null) {
                logger.debugf("Valid Until set for Metadata. Setting valid until current date + %s %s",
                        getConfig().getMetadataValidUntilUnit(), getConfig().getMetadataValidUntilPeriod());
                spMetadataDescriptorBuilder
                        .metadataValidUntilUnit(getConfig().getMetadataValidUntilUnit())
                        .metadataValidUntilPeriod(getConfig().getMetadataValidUntilPeriod());
            }
            EntityDescriptorType entityDescriptor = spMetadataDescriptorBuilder.build();

            // Assuming AttributeConsumingServiceType.getServices() returns a list of AttributeConsumingService objects.
            List<String> attributeValues = getConfig().getAttributeConsumingServiceValues();
            if(!attributeValues.isEmpty()) {
                int attributeConsumingServiceIndex = 1;
                int defaultAttributeConsumingServiceIndex = getConfig().getAttributeConsumingServiceIndex() != null ? getConfig().getAttributeConsumingServiceIndex() : 1;

                for(String attributeValue : attributeValues) {
                    String attributeConsumingServiceName = getConfig().getAttributeConsumingServiceName();
                    //default value for attributeConsumingServiceName
                    if (attributeConsumingServiceName == null)
                        attributeConsumingServiceName = realm.getDisplayName() != null ? realm.getDisplayName() : realm.getName();
//                    attributeConsumingServiceName += "_" + attributeConsumingServiceIndex;

                    AttributeConsumingServiceType attributeConsumingService = new AttributeConsumingServiceType(attributeConsumingServiceIndex);
                    attributeConsumingService.setIsDefault((attributeConsumingServiceIndex == defaultAttributeConsumingServiceIndex));

                    String currentLocale = realm.getDefaultLocale() == null ? "en" : realm.getDefaultLocale();
                    LocalizedNameType attributeConsumingServiceNameElement = new LocalizedNameType(currentLocale);
                    attributeConsumingServiceNameElement.setValue(attributeConsumingServiceName);
                    attributeConsumingService.addServiceName(attributeConsumingServiceNameElement);

                    String attributeName = "urn:nl-eid-gdi:1.0:ServiceUUID";
                    String attributeFriendlyName = "ServiceUUID_" + attributeConsumingServiceIndex;

                    RequestedAttributeType requestedAttribute = new RequestedAttributeType(attributeName);
                    requestedAttribute.setIsRequired(null);
                    requestedAttribute.setNameFormat(ATTRIBUTE_FORMAT_BASIC.get());

                    if (attributeFriendlyName != null && attributeFriendlyName.length() > 0)
                        requestedAttribute.setFriendlyName(attributeFriendlyName);

                    if (attributeValue != null && attributeValue.length() > 0)
                        requestedAttribute.addAttributeValue(attributeValue);

                    boolean alreadyPresent = attributeConsumingService.getRequestedAttribute().stream()
                            .anyMatch(t -> (attributeName == null || attributeName.equalsIgnoreCase(t.getName())) &&
                                    (attributeFriendlyName == null || attributeFriendlyName.equalsIgnoreCase(t.getFriendlyName())));

                    if (!alreadyPresent) {
                        logger.debugf("%s not present adding to Attribute Consuming Service", attributeName);
                        attributeConsumingService.addRequestedAttribute(requestedAttribute);
                    } else {
                        logger.warnf("%s is present not adding to Attribute Consuming Service", attributeName);
                    }

                    for (EntityDescriptorType.EDTChoiceType choiceType : entityDescriptor.getChoiceType()) {
                        List<EntityDescriptorType.EDTDescriptorChoiceType> descriptors = choiceType.getDescriptors();
                        for (EntityDescriptorType.EDTDescriptorChoiceType descriptor : descriptors) {
                            descriptor.getSpDescriptor().addAttributeConsumerService(attributeConsumingService);
                        }
                    }

                    attributeConsumingServiceIndex++;
                }
            }

            // Write the metadata and export it to a string
            logger.debug("Write the metadata and export it to a string");
            metadataWriter.writeEntityDescriptor(entityDescriptor);

            String descriptor = sw.toString();
            logger.tracef("Unsigned metadata:\n\t %s",descriptor);

            // Metadata signing
            if (getConfig().isSignSpMetadata())
            {
                KeyManager.ActiveRsaKey activeKey = session.keys().getActiveRsaKey(realm);
                String keyName = getConfig().getXmlSigKeyInfoKeyNameTransformer().getKeyName(activeKey.getKid(), activeKey.getCertificate());
                KeyPair keyPair = new KeyPair(activeKey.getPublicKey(), activeKey.getPrivateKey());

                Document metadataDocument = DocumentUtil.getDocument(descriptor);
                SAML2Signature signatureHelper = new SAML2Signature();
                signatureHelper.setSignatureMethod(getSignatureAlgorithm().getXmlSignatureMethod());
                signatureHelper.setDigestMethod(getSignatureAlgorithm().getXmlSignatureDigestMethod());

                Node nextSibling = metadataDocument.getDocumentElement().getFirstChild();
                signatureHelper.setNextSibling(nextSibling);

                signatureHelper.signSAMLDocument(metadataDocument, keyName, keyPair, CanonicalizationMethod.EXCLUSIVE);

                descriptor = DocumentUtil.getDocumentAsString(metadataDocument);
            }

            return Response.ok(descriptor, MediaType.APPLICATION_XML_TYPE).build();
        } catch (Exception e) {
            logger.warn("Failed to export SAML SP Metadata!", e);
            throw new RuntimeException(e);
        }
    }

    public SignatureAlgorithm getSignatureAlgorithm() {
        String alg = getConfig().getSignatureAlgorithm();
        if (alg != null) {
            SignatureAlgorithm algorithm = SignatureAlgorithm.valueOf(alg);
            if (algorithm != null) return algorithm;
        }
        return SignatureAlgorithm.RSA_SHA256;
    }

    @Override
    public IdentityProviderDataMarshaller getMarshaller() {
        return new SAMLDataMarshaller();
    }
}
