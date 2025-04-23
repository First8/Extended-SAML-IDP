package nl.first8.keycloak.broker.saml.mappers;

import nl.first8.keycloak.broker.saml.SAMLEndpoint;
import nl.first8.keycloak.broker.saml.SAMLIdentityProviderFactory;
import nl.first8.keycloak.dom.saml.v2.assertion.AssertionType;
import nl.first8.keycloak.dom.saml.v2.assertion.AttributeStatementType;
import nl.first8.keycloak.dom.saml.v2.assertion.SAMLEncryptedType;
import nl.first8.keycloak.dom.saml.v2.assertion.SamlEncryptedId;
import nl.first8.keycloak.dom.saml.v2.metadata.AttributeConsumingServiceType;
import nl.first8.keycloak.dom.saml.v2.metadata.EntityDescriptorType;
import nl.first8.keycloak.protocol.saml.mappers.SamlMetadataDescriptorUpdater;
import nl.first8.keycloak.saml.encryption.DecryptionException;
import nl.first8.keycloak.saml.encryption.SamlDecrypter;
import org.apache.commons.lang3.StringUtils;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.AbstractIdentityProviderMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.common.util.CollectionUtil;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.dom.saml.v2.assertion.AttributeType;
import org.keycloak.dom.saml.v2.assertion.NameIDType;
import org.keycloak.dom.saml.v2.metadata.RequestedAttributeType;
import org.keycloak.models.*;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;
import org.keycloak.saml.common.util.StringUtil;

import java.nio.charset.StandardCharsets;
import java.security.PrivateKey;
import java.util.*;
import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import static org.keycloak.saml.common.constants.JBossSAMLURIConstants.ATTRIBUTE_FORMAT_BASIC;

public class UserAttributeMapper extends AbstractIdentityProviderMapper implements SamlMetadataDescriptorUpdater {

    protected static final Logger logger = Logger.getLogger(UserAttributeMapper.class);

    public static final String[] COMPATIBLE_PROVIDERS = {SAMLIdentityProviderFactory.PROVIDER_ID};

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    public static final String ATTRIBUTE_DECRYPT = "attribute.decrypt";
    public static final String ATTRIBUTE_XACML_CONTEXT = "attribute.xacml-context";
    public static final String ATTRIBUTE_NAME = "attribute.name";
    public static final String ATTRIBUTE_VALUE = "attribute.value";
    public static final String ATTRIBUTE_FRIENDLY_NAME = "attribute.friendly.name";
    public static final String ATTRIBUTE_NAME_FORMAT = "attribute.name.format";
    public static final String USER_ATTRIBUTE = "user.attribute";
    public static final String XML_ELEMENT_AS_ATTRIBUTE = "attribute.xml.element";
    private static final String ID = "id";
    private static final String EMAIL = "email";
    private static final String FIRST_NAME = "firstName";
    private static final String LAST_NAME = "lastName";
    private static final Set<IdentityProviderSyncMode> IDENTITY_PROVIDER_SYNC_MODES = new HashSet<>(Arrays.asList(IdentityProviderSyncMode.values()));

    public static final List<String> NAME_FORMATS = Arrays.asList(JBossSAMLURIConstants.ATTRIBUTE_FORMAT_BASIC.name(), JBossSAMLURIConstants.ATTRIBUTE_FORMAT_URI.name(), JBossSAMLURIConstants.ATTRIBUTE_FORMAT_UNSPECIFIED.name());
    static {
        ProviderConfigProperty property;
        property = new ProviderConfigProperty();
        property.setName(ATTRIBUTE_NAME);
        property.setLabel("Attribute Name");
        property.setHelpText("Name of attribute to search for in assertion.  You can leave this blank and specify a friendly name instead.");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        configProperties.add(property);
        property = new ProviderConfigProperty();
        property.setName(ATTRIBUTE_FRIENDLY_NAME);
        property.setLabel("Friendly Name");
        property.setHelpText("Friendly name of attribute to search for in assertion.  You can leave this blank and specify a name instead.");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        configProperties.add(property);
        property = new ProviderConfigProperty();
        property.setName(ATTRIBUTE_NAME_FORMAT);
        property.setLabel("Name Format");
        property.setHelpText("Name format of attribute to specify in the RequestedAttribute element. Default to basic format.");
        property.setType(ProviderConfigProperty.LIST_TYPE);
        property.setOptions(NAME_FORMATS);
        property.setDefaultValue(JBossSAMLURIConstants.ATTRIBUTE_FORMAT_BASIC.name());
        configProperties.add(property);
        property = new ProviderConfigProperty();
        property.setName(USER_ATTRIBUTE);
        property.setLabel("User Attribute Name");
        property.setHelpText("User attribute name to store saml attribute.  Use id, email, lastName, and firstName to map to those predefined user properties.");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        configProperties.add(property);
        property = new ProviderConfigProperty();
        property.setName(XML_ELEMENT_AS_ATTRIBUTE);
        property.setLabel("Encrypted ID as Attribute");
        property.setHelpText("Set the complete XML Element EncryptedID as attribute (Base64 encoded).");
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        configProperties.add(property);
        property = new ProviderConfigProperty();
        property.setName(ATTRIBUTE_DECRYPT);
        property.setLabel("Decrypt Attribute");
        property.setHelpText("Decrypt the value and set the decrypted value in the property.");
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        configProperties.add(property);
        property = new ProviderConfigProperty();
        property.setName(ATTRIBUTE_XACML_CONTEXT);
        property.setLabel("Use XamlResource attributes");
        property.setHelpText("Gets the attributes from the <xacml-context:Resource> instead of the <saml2:AttributeStatement> tag");
        property.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        configProperties.add(property);
    }

    public static final String PROVIDER_ID = "saml-extended-user-attribute-idp-mapper";

    @Override
    public boolean supportsSyncMode(IdentityProviderSyncMode syncMode) {
        return IDENTITY_PROVIDER_SYNC_MODES.contains(syncMode);
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String[] getCompatibleProviders() {
        return COMPATIBLE_PROVIDERS;
    }

    @Override
    public String getDisplayCategory() {
        return "Attribute Importer";
    }

    @Override
    public String getDisplayType() {
        return "Attribute Importer";
    }

    @Override
    public void preprocessFederatedIdentity(KeycloakSession session, RealmModel realm, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        logger.debug("Preprocess Federated Identity");
        logContext(context, null);
        String attribute = mapperModel.getConfig().get(USER_ATTRIBUTE);
        if (StringUtil.isNullOrEmpty(attribute)) {
            return;
        }
        String attributeName = getAttributeNameFromMapperModel(mapperModel);

        KeyWrapper keys = session.keys().getActiveKey(realm, KeyUse.SIG, Algorithm.RS256);
        List<String> attributeValuesInContext = findAttributeValuesInContext(attributeName, context, mapperModel, keys);
        logger.debugf("Found %d attributes for `%s`", attributeValuesInContext.size(), attributeName);
        if (!attributeValuesInContext.isEmpty()) {
            logger.debugf("Setting attribute as %s", attribute);
            if (attribute.equalsIgnoreCase(ID)) {
                setIfNotEmpty(context::setId, attributeValuesInContext);
            } else if (attribute.equalsIgnoreCase(EMAIL)) {
                setIfNotEmptyAndStripMailto(context::setEmail, attributeValuesInContext);
            } else if (attribute.equalsIgnoreCase(FIRST_NAME)) {
                setIfNotEmpty(context::setFirstName, attributeValuesInContext);
            } else if (attribute.equalsIgnoreCase(LAST_NAME)) {
                setIfNotEmpty(context::setLastName, attributeValuesInContext);
            } else {
                context.setUserAttribute(attribute, attributeValuesInContext);
            }
        }

        logContext(context, null);
        logger.tracef("BrokeredIdentityContext attribute `%s` has been set to `%s`.", attribute, context.getUserAttribute(attribute));

    }

    private static void logContext(BrokeredIdentityContext context, UserModel user) {
        if(logger.isTraceEnabled()) {
            logger.tracef("Listing of known BrokeredIdentityContext attributes: ");
            for(Map.Entry<String, Object> contextAttribute : context.getContextData().entrySet()) {
                logger.tracef("\t Attribute `%s` with values ", contextAttribute.getKey());
                if(contextAttribute.getValue() instanceof String) {
                    logger.tracef("\t\t value: `%s`", contextAttribute.getValue());
                } else if(contextAttribute.getValue() instanceof ArrayList) {
                    for(Object arListValue : (ArrayList<String>)contextAttribute.getValue()) {
                        logger.tracef("\t\t value: `%s`", arListValue);
                    }
                } else {
                    logger.tracef("\t\t value is of type `%s`", contextAttribute.getValue().getClass().getName());
                }
            }
        }

        if(logger.isTraceEnabled()) {
            if (user != null) {
                logger.tracef("Listing of known user attributes: ");
                for(Map.Entry<String, List<String>> userAttribute : user.getAttributes().entrySet()) {
                    logger.tracef("\t Attribute `%s` with values ", userAttribute.getKey());
                    for(String value : userAttribute.getValue()) {
                        logger.tracef("\t\t value: `%s`", value);
                    }
                }
            } else {
                logger.tracef("User attributes are not known");
            }
        }
    }

    private String getAttributeNameFromMapperModel(IdentityProviderMapperModel mapperModel) {
        String attributeName = mapperModel.getConfig().get(ATTRIBUTE_NAME);
        if (attributeName == null) {
            attributeName = mapperModel.getConfig().get(ATTRIBUTE_FRIENDLY_NAME);
        }
        return attributeName;
    }

    private void setIfNotEmpty(Consumer<String> consumer, List<String> values) {
        if (values != null && !values.isEmpty()) {
            consumer.accept(values.get(0));
        }
    }


    private void setIfNotEmptyAndDifferent(Consumer<String> consumer, Supplier<String> currentValueSupplier, List<String> values) {
        if (values != null && !values.isEmpty() && !values.get(0).equals(currentValueSupplier.get())) {
            consumer.accept(values.get(0));
        }
    }
    private void setIfNotEmptyAndStripMailto(Consumer<String> consumer, List<String> values) {
        if (values != null && !values.isEmpty()) {
            consumer.accept(values.get(0).replace("mailto:",""));
        }
    }

    private void setIfNotEmptyAndDifferentAndStripMailto(Consumer<String> consumer, Supplier<String> currentValueSupplier, List<String> values) {
        if (values != null && !values.isEmpty() && !values.get(0).equals(currentValueSupplier.get())) {
            consumer.accept(values.get(0).replace("mailto:",""));
        }
    }


    private Predicate<AttributeStatementType.ASTChoiceType> elementWith(String attributeName) {
        return attributeType -> {
            AttributeType attribute = attributeType.getAttribute();
            return hasMatchingNameOrFriendlyName(attributeName).test(attribute);
        };
    }

    private Predicate<AttributeType> hasMatchingNameOrFriendlyName(String attributeName) {
        return attribute -> {
            String name = attribute.getName();
            String friendlyName = attribute.getFriendlyName();
            boolean eqName = attributeName.equals(name);
            boolean eqFriendlyName = attributeName.equals(friendlyName);
            boolean isElementWith = eqName
                    || eqFriendlyName;
            if(logger.isTraceEnabled()) {
                logger.tracef("Searching for: `%s`. Found Name: `%s` (%b) or FriendlyName: `%s` (%b) -> %b",
                        attributeName, name, eqName, friendlyName, eqFriendlyName, isElementWith);
                if(!isElementWith) {
                    String diffName = StringUtils.difference(name, attributeName);
                    String diffFriendlyName = StringUtils.difference(friendlyName, attributeName);
                    logger.tracef("Difference between strings: \n\tName: `%s`, FriendlyName: `%s`", diffName, diffFriendlyName);
                }
            }
            return isElementWith;
        };
    }


    private List<String> findAttributeValuesInContext(String attributeName, BrokeredIdentityContext context, IdentityProviderMapperModel mapperModel, KeyWrapper keys) {
        AssertionType assertion = (AssertionType) context.getContextData().get(SAMLEndpoint.SAML_ASSERTION);

        if(Boolean.valueOf(mapperModel.getConfig().get(ATTRIBUTE_XACML_CONTEXT))) {
            logger.debugf("Searching for Attribute `%s` in Xacml context.", attributeName);
            return assertion.getXacmlResources().stream()
                    .flatMap(resource -> resource.getAttributes().stream())
                    .filter(hasMatchingNameOrFriendlyName(attributeName))
                    .flatMap(attribute -> attribute.getAttributeValue().stream())
                    .filter(Objects::nonNull)
                    .findFirst()
                    .map(object -> assignValue(mapperModel, object, keys))
                    .map(List::of)
                    .orElse(List.of());
        }
        logger.debugf("Searching for Attribute `%s` in Attribute Context.", attributeName);
        return assertion.getAttributeStatements().stream()
                .flatMap(statement -> statement.getAttributes().stream())
                .filter(elementWith(attributeName))
                .flatMap(attributeType -> attributeType.getAttribute().getAttributeValue().stream())
                .filter(Objects::nonNull)
                .map(object -> assignValue(mapperModel, object, keys))
                .collect(Collectors.toList());
    }

    private String assignValue(IdentityProviderMapperModel mapperModel, Object object, KeyWrapper keys) {
        if(logger.isDebugEnabled()) {
            String attributeName = getAttributeNameFromMapperModel(mapperModel);
            logger.debugf("Assigning value for `%s`.", attributeName);
        }
        String value = object.toString();
        if(Boolean.valueOf(mapperModel.getConfig().get(XML_ELEMENT_AS_ATTRIBUTE))) {
            logger.debug("Assigning value as Base64 of XML attribute");
            value = Base64.getEncoder().encodeToString(value.getBytes(StandardCharsets.UTF_8));
        } else if(Boolean.valueOf(mapperModel.getConfig().get(ATTRIBUTE_DECRYPT))) {
            logger.debug("Decrypting Attribute and assigning value");
            if(object instanceof SamlEncryptedId) {
                try {
                    NameIDType nameID = SamlDecrypter.decryptToNameID((SAMLEncryptedType) object, (PrivateKey) keys.getPrivateKey());
                    value = nameID.getValue();
                } catch (DecryptionException e) {
                    logger.warn("Error when decrypting attribute value. Trying decrypting to plain text.");
                    try {
                        value = new String(SamlDecrypter.decrypt((SAMLEncryptedType) object, (PrivateKey) keys.getPrivateKey()));
                    } catch (DecryptionException ex) {
                        logger.error("Error when decrypting attribute to plain text.", e);
                    }
                }
            } else {
                logger.warnf("Object ('%s') not of type EncryptedID cannot be decrypted.", object.getClass().getName());
            }
        }
        logger.debugf("Value found: %s", value);
        return value;
    }

    @Override
    public void updateBrokeredUser(KeycloakSession session, RealmModel realm, UserModel user, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        logger.debug("Update Brokered User.");
        logContext(context, user);
        String attribute = mapperModel.getConfig().get(USER_ATTRIBUTE);
        if (StringUtil.isNullOrEmpty(attribute)) {
            return;
        }
        String attributeName = getAttributeNameFromMapperModel(mapperModel);
        KeyWrapper keys = session.keys().getActiveKey(realm, KeyUse.SIG, Algorithm.RS256);

        List<String> attributeValuesInContext = findAttributeValuesInContext(attributeName, context, mapperModel, keys);
        logger.debugf("Found %d attributes in BrokeredIdentityContext for `%s`. Setting user attribute as %s", attributeValuesInContext.size(), attributeName, attribute);
        if (attribute.equalsIgnoreCase(EMAIL)) {
            setIfNotEmptyAndDifferentAndStripMailto(user::setEmail, user::getEmail, attributeValuesInContext);
        } else if (attribute.equalsIgnoreCase(FIRST_NAME)) {
            setIfNotEmptyAndDifferent(user::setFirstName, user::getFirstName, attributeValuesInContext);
        } else if (attribute.equalsIgnoreCase(LAST_NAME)) {
            setIfNotEmptyAndDifferent(user::setLastName, user::getLastName, attributeValuesInContext);
        } else {
            logger.debugf("Attribute `%s` not of known type(`%s`, `%s`, `%s`). So setting custom user attribute.", attribute, EMAIL, FIRST_NAME, LAST_NAME);
            List<String> currentAttributeValues = user.getAttributes().get(attribute);
            if (attributeValuesInContext == null) {
                logger.debug("Attribute no longer sent by brokered idp, remove from user attributes");
                // attribute no longer sent by brokered idp, remove it.
                user.removeAttribute(attribute);
            } else if (currentAttributeValues == null) {
                logger.debug("New attribute sent by brokered idp, add to user attributes");
                // new attribute sent by brokered idp, add it.
                user.setAttribute(attribute, attributeValuesInContext);
            } else if (!CollectionUtil.collectionEquals(attributeValuesInContext, currentAttributeValues)) {
                logger.debug("Attribute sent by brokered idp has different values as before, update user attribute");
                // attribute sent by brokered idp has different values as before, update it.
                user.setAttribute(attribute, attributeValuesInContext);
            } else {
                logger.debug("Unknown attribute or what to do with it");
            }

            // attribute already set.
        }

        logContext(context, user);
        logger.tracef("User attribute `%s` has been set to `%s`.", attribute, user.getFirstAttribute(attribute));

    }

    @Override
    public String getHelpText() {
        return "Import declared saml attribute if it exists in assertion into the specified user property or attribute.";
    }

    // SamlMetadataDescriptorUpdater interface
    @Override
    public void updateMetadata(IdentityProviderMapperModel mapperModel, EntityDescriptorType entityDescriptor) {
        String attributeName = mapperModel.getConfig().get(org.keycloak.broker.saml.mappers.UserAttributeMapper.ATTRIBUTE_NAME);
        String attributeFriendlyName = mapperModel.getConfig().get(org.keycloak.broker.saml.mappers.UserAttributeMapper.ATTRIBUTE_FRIENDLY_NAME);

        RequestedAttributeType requestedAttribute = new RequestedAttributeType(attributeName);
        requestedAttribute.setIsRequired(null);
        requestedAttribute.setNameFormat(mapperModel.getConfig().get(org.keycloak.broker.saml.mappers.UserAttributeMapper.ATTRIBUTE_NAME_FORMAT) != null ? JBossSAMLURIConstants.valueOf(mapperModel.getConfig().get(org.keycloak.broker.saml.mappers.UserAttributeMapper.ATTRIBUTE_NAME_FORMAT)).get() :ATTRIBUTE_FORMAT_BASIC.get());

        if (attributeFriendlyName != null && attributeFriendlyName.length() > 0)
            requestedAttribute.setFriendlyName(attributeFriendlyName);

        // Add the requestedAttribute item to any AttributeConsumingServices
        for (EntityDescriptorType.EDTChoiceType choiceType : entityDescriptor.getChoiceType()) {
            List<EntityDescriptorType.EDTDescriptorChoiceType> descriptors = choiceType.getDescriptors();
            for (EntityDescriptorType.EDTDescriptorChoiceType descriptor : descriptors) {
                for (AttributeConsumingServiceType attributeConsumingService : descriptor.getSpDescriptor().getAttributeConsumingService()) {
                    boolean alreadyPresent = attributeConsumingService.getRequestedAttribute().stream()
                            .anyMatch(t -> (attributeName == null || attributeName.equalsIgnoreCase(t.getName())) &&
                                    (attributeFriendlyName == null || attributeFriendlyName.equalsIgnoreCase(t.getFriendlyName())));

                    if (!alreadyPresent)
                        attributeConsumingService.addRequestedAttribute(requestedAttribute);
                }
            }

        }
    }
}
