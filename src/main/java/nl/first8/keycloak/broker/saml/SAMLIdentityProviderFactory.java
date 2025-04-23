package nl.first8.keycloak.broker.saml;

import nl.first8.keycloak.dom.saml.v2.metadata.EntitiesDescriptorType;
import nl.first8.keycloak.dom.saml.v2.metadata.EntityDescriptorType;
import nl.first8.keycloak.saml.processing.core.parsers.saml.SAMLParser;
import org.jboss.logging.Logger;
import org.keycloak.Config;
import org.keycloak.broker.provider.AbstractIdentityProviderFactory;
import org.keycloak.dom.saml.v2.metadata.*;
import org.keycloak.models.IdentityProviderModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;
import org.keycloak.saml.common.exceptions.ParsingException;
import org.keycloak.saml.common.util.DocumentUtil;
import org.keycloak.saml.validators.DestinationValidator;
import org.w3c.dom.Element;

import javax.xml.namespace.QName;
import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.util.*;

public class SAMLIdentityProviderFactory extends AbstractIdentityProviderFactory<SAMLIdentityProvider> {
    protected static final Logger logger = Logger.getLogger(SAMLIdentityProviderFactory.class);

    public static final String PROVIDER_ID = "saml-extended";

    private static final String PROVIDER_NAME = "SAML v2.0 - Extended";
    private DestinationValidator destinationValidator;

    public SAMLIdentityProviderFactory() {
        logger.info("Initialized Identity Provider Factory for " + getName());
    }

    @Override
    public String getName() {
        return PROVIDER_NAME;
    }

    @Override
    public SAMLIdentityProvider create(KeycloakSession session, IdentityProviderModel model) {
        return new SAMLIdentityProvider(session, new SAMLIdentityProviderConfig(model), destinationValidator);
    }

    @Override
    public SAMLIdentityProviderConfig createConfig() {
        return new SAMLIdentityProviderConfig();
    }

    @Override
    public Map<String, String> parseConfig(KeycloakSession session, String xmlContent) {
        try {
            InputStream inputStream = new ByteArrayInputStream(xmlContent.getBytes("UTF-8"));

            // Use the XML content string for parsing
            SAMLParser parser = SAMLParser.getInstance();
            logger.debugf("SAMLParser in use: %s", parser.getClass());
            Object parsedObject = parser.parse(inputStream);
            EntityDescriptorType entityType;

            if (EntitiesDescriptorType.class.isInstance(parsedObject)) {
                entityType = (EntityDescriptorType) ((EntitiesDescriptorType) parsedObject).getEntityDescriptor().get(0);
            } else {
                entityType = (EntityDescriptorType) parsedObject;
            }


            List<EntityDescriptorType.EDTChoiceType> choiceType = entityType.getChoiceType();

            if (!choiceType.isEmpty()) {
                IDPSSODescriptorType idpDescriptor = null;

                //Metadata documents can contain multiple Descriptors (See ADFS metadata documents) such as RoleDescriptor, SPSSODescriptor, IDPSSODescriptor.
                //So we need to loop through to find the IDPSSODescriptor.
                for (EntityDescriptorType.EDTChoiceType edtChoiceType : entityType.getChoiceType()) {
                    List<EntityDescriptorType.EDTDescriptorChoiceType> descriptors = edtChoiceType.getDescriptors();

                    if (!descriptors.isEmpty() && descriptors.get(0).getIdpDescriptor() != null) {
                        idpDescriptor = descriptors.get(0).getIdpDescriptor();
                    }
                }


                if (idpDescriptor != null) {
                    SAMLIdentityProviderConfig samlIdentityProviderConfig = new SAMLIdentityProviderConfig();
                    String singleSignOnServiceUrl = null;
                    boolean postBindingResponse = false;
                    boolean postBindingLogout = false;
                    boolean artifactResolution = false;
                    boolean soapArtifactResolution = false;
                    for (EndpointType endpoint : idpDescriptor.getSingleSignOnService()) {
                        if (endpoint.getBinding().toString().equals(JBossSAMLURIConstants.SAML_HTTP_POST_BINDING.get())) {
                            singleSignOnServiceUrl = endpoint.getLocation().toString();
                            postBindingResponse = true;
                            break;
                        } else if (endpoint.getBinding().toString().equals(JBossSAMLURIConstants.SAML_HTTP_REDIRECT_BINDING.get())) {
                            singleSignOnServiceUrl = endpoint.getLocation().toString();
                        }
                    }
                    String singleLogoutServiceUrl = null;
                    for (EndpointType endpoint : idpDescriptor.getSingleLogoutService()) {
                        if (postBindingResponse && endpoint.getBinding().toString().equals(JBossSAMLURIConstants.SAML_HTTP_POST_BINDING.get())) {
                            singleLogoutServiceUrl = endpoint.getLocation().toString();
                            postBindingLogout = true;
                            break;
                        } else if (!postBindingResponse && endpoint.getBinding().toString().equals(JBossSAMLURIConstants.SAML_HTTP_REDIRECT_BINDING.get())) {
                            singleLogoutServiceUrl = endpoint.getLocation().toString();
                            break;
                        }
                    }
                    String artifactResolutionUrl = null;
                    for (IndexedEndpointType endpoint : idpDescriptor.getArtifactResolutionService()) {
                        artifactResolution = true;
                        if (endpoint.getBinding().toString().equals(JBossSAMLURIConstants.SAML_SOAP_BINDING.get())) {
                            soapArtifactResolution = true;
                        }
                        artifactResolutionUrl = endpoint.getLocation().toString();
                    }
                    samlIdentityProviderConfig.setIdpEntityId(entityType.getEntityID());
                    samlIdentityProviderConfig.setSingleLogoutServiceUrl(singleLogoutServiceUrl);
                    samlIdentityProviderConfig.setSingleSignOnServiceUrl(singleSignOnServiceUrl);
                    samlIdentityProviderConfig.setArtifactResolution(artifactResolution);
                    samlIdentityProviderConfig.setArtifactResolutionEndpoint(artifactResolutionUrl);
                    samlIdentityProviderConfig.setArtifactResolutionSOAP(soapArtifactResolution);
                    samlIdentityProviderConfig.setWantAuthnRequestsSigned(idpDescriptor.isWantAuthnRequestsSigned());
                    samlIdentityProviderConfig.setAddExtensionsElementWithKeyInfo(false);
                    samlIdentityProviderConfig.setValidateSignature(idpDescriptor.isWantAuthnRequestsSigned());
                    samlIdentityProviderConfig.setPostBindingResponse(postBindingResponse);
                    samlIdentityProviderConfig.setPostBindingAuthnRequest(postBindingResponse);
                    samlIdentityProviderConfig.setPostBindingLogout(postBindingLogout);
                    samlIdentityProviderConfig.setLoginHint(false);

                    List<String> nameIdFormatList = idpDescriptor.getNameIDFormat();
                    if (nameIdFormatList != null && !nameIdFormatList.isEmpty()) {
                        samlIdentityProviderConfig.setNameIDPolicyFormat(nameIdFormatList.get(0));
                    }
                    List<KeyDescriptorType> keyDescriptor = idpDescriptor.getKeyDescriptor();
                    String defaultCertificate = null;

                    if (keyDescriptor != null) {
                        for (KeyDescriptorType keyDescriptorType : keyDescriptor) {
                            Element keyInfo = keyDescriptorType.getKeyInfo();
                            Element x509KeyInfo = DocumentUtil.getChildElement(keyInfo, new QName("dsig", "X509Certificate"));

                            if (KeyTypes.SIGNING.equals(keyDescriptorType.getUse())) {
                                samlIdentityProviderConfig.addSigningCertificate(x509KeyInfo.getTextContent());
                            } else if (KeyTypes.ENCRYPTION.equals(keyDescriptorType.getUse())) {
                                samlIdentityProviderConfig.setEncryptionPublicKey(x509KeyInfo.getTextContent());
                            } else if (keyDescriptorType.getUse() == null) {
                                defaultCertificate = x509KeyInfo.getTextContent();
                            }
                        }
                    }

                    if (defaultCertificate != null) {
                        if (samlIdentityProviderConfig.getSigningCertificates().length == 0) {
                            samlIdentityProviderConfig.addSigningCertificate(defaultCertificate);
                        }

                        if (samlIdentityProviderConfig.getEncryptionPublicKey() == null) {
                            samlIdentityProviderConfig.setEncryptionPublicKey(defaultCertificate);
                        }
                    }

                    samlIdentityProviderConfig.setEnabledFromMetadata(entityType.getValidUntil() == null
                            || entityType.getValidUntil().toGregorianCalendar().getTime().after(new Date(System.currentTimeMillis())));

                    // (There used to be a check here that we removed pre-emptively, since it used a deprecated method, and deprecated site in a value.)

                    return samlIdentityProviderConfig.getConfig();
                }
            }
        } catch (ParsingException pe) {
            throw new RuntimeException("Could not parse IdP SAML Metadata", pe);
        } catch (UnsupportedEncodingException e) {
            throw new RuntimeException(e);
        }
        return new HashMap<>();
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public void init(Config.Scope config) {
        super.init(config);

        this.destinationValidator = DestinationValidator.forProtocolMap(config.getArray("knownProtocols"));
    }
}
