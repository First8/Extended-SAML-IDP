package nl.first8.keycloak.broker.saml.mappers;

import nl.first8.keycloak.broker.saml.SAMLEndpoint;
import nl.first8.keycloak.broker.saml.SAMLIdentityProviderFactory;
import nl.first8.keycloak.dom.saml.v2.assertion.AssertionType;
import nl.first8.keycloak.dom.saml.v2.assertion.AttributeStatementType;
import nl.first8.keycloak.dom.saml.v2.assertion.XacmlResourceType;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.broker.provider.ConfigConstants;
import org.keycloak.broker.saml.mappers.AbstractAttributeToRoleMapper;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderSyncMode;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.*;
import java.util.stream.Collectors;

import static org.keycloak.utils.RegexUtils.valueMatchesRegex;

public class AdvancedAttributeToRoleMapper extends AbstractAttributeToRoleMapper {

    public static final String PROVIDER_ID = "saml-extended-advanced-role-idp-mapper";
    public static final String ATTRIBUTE_PROPERTY_NAME = "attributes";
    public static final String ATTRIBUTE_XACML_CONTEXT = "attribute.xacml-context";
    public static final String ARE_ATTRIBUTE_VALUES_REGEX_PROPERTY_NAME = "are.attribute.values.regex";

    private static final Set<IdentityProviderSyncMode> IDENTITY_PROVIDER_SYNC_MODES = new HashSet<>(Arrays.asList(IdentityProviderSyncMode.values()));

    public static final String[] COMPATIBLE_PROVIDERS = {
            SAMLIdentityProviderFactory.PROVIDER_ID
    };

    private static final List<ProviderConfigProperty> configProperties =
            new ArrayList<>();

    static {
        ProviderConfigProperty attributeMappingProperty = new ProviderConfigProperty();
        attributeMappingProperty.setName(ATTRIBUTE_PROPERTY_NAME);
        attributeMappingProperty.setLabel("Attributes");
        attributeMappingProperty.setHelpText(
                "Name and (regex) value of the attributes to search for in token. "
                        + " The configured name of an attribute is searched in SAML attribute name and attribute friendly name fields."
                        + " Every given attribute description must be met to set the role."
                        + " If the attribute is an array, then the value must be contained in the array."
                        + " If an attribute can be found several times, then one match is sufficient.");
        attributeMappingProperty.setType(ProviderConfigProperty.MAP_TYPE);
        configProperties.add(attributeMappingProperty);

        ProviderConfigProperty isAttributeRegexProperty = new ProviderConfigProperty();
        isAttributeRegexProperty.setName(ARE_ATTRIBUTE_VALUES_REGEX_PROPERTY_NAME);
        isAttributeRegexProperty.setLabel("Regex Attribute Values");
        isAttributeRegexProperty.setHelpText("If enabled attribute values are interpreted as regular expressions.");
        isAttributeRegexProperty.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        configProperties.add(isAttributeRegexProperty);

        ProviderConfigProperty roleProperty = new ProviderConfigProperty();
        roleProperty.setName(ConfigConstants.ROLE);
        roleProperty.setLabel("Role");
        roleProperty.setHelpText("Role to grant to user if all attributes are present."
                + " Click 'Select Role' button to browse roles, or just type it in the textbox."
                + " To reference a client role the syntax is clientname.clientrole, i.e. myclient.myrole");
        roleProperty.setType(ProviderConfigProperty.ROLE_TYPE);
        configProperties.add(roleProperty);

        ProviderConfigProperty xacmlResourceProperty = new ProviderConfigProperty();
        xacmlResourceProperty.setName(ATTRIBUTE_XACML_CONTEXT);
        xacmlResourceProperty.setLabel("Use XamlResource attributes");
        xacmlResourceProperty.setHelpText("Gets the attributes from the <xacml-context:Resource> instead of the <saml2:AttributeStatement> tag");
        xacmlResourceProperty.setType(ProviderConfigProperty.BOOLEAN_TYPE);
        configProperties.add(xacmlResourceProperty);

    }

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
        return "Role Importer";
    }

    @Override
    public String getDisplayType() {
        return "Advanced Attribute to Role";
    }

    @Override
    public String getHelpText() {
        return "If the set of attributes exists and can be matched, grant the user the specified realm or client role.";
    }

    protected boolean applies(final IdentityProviderMapperModel mapperModel, final BrokeredIdentityContext context) {
        Map<String, String> attributes = mapperModel.getConfigMap(ATTRIBUTE_PROPERTY_NAME);
        boolean areAttributeValuesRegexes = Boolean.parseBoolean(mapperModel.getConfig().get(ARE_ATTRIBUTE_VALUES_REGEX_PROPERTY_NAME));

        AssertionType assertion = (AssertionType) context.getContextData().get(SAMLEndpoint.SAML_ASSERTION);
        Set<AttributeStatementType> attributeAssertions = assertion.getAttributeStatements();
        if (attributeAssertions == null && !Boolean.valueOf(mapperModel.getConfig().get(ATTRIBUTE_XACML_CONTEXT))) {
            return false;
        }

        Set<XacmlResourceType> xacmlAssertionResources = assertion.getXacmlResources();
        if (xacmlAssertionResources == null && Boolean.valueOf(mapperModel.getConfig().get(ATTRIBUTE_XACML_CONTEXT))) {
            return false;
        }

        for (Map.Entry<String, String> attribute : attributes.entrySet()) {
            String attributeKey = attribute.getKey();
            List<Object> attributeValues;
            if(Boolean.valueOf(mapperModel.getConfig().get(ATTRIBUTE_XACML_CONTEXT))) {
                attributeValues = appliesXacmlResource(xacmlAssertionResources, attributeKey);
            }
            else{
                attributeValues = appliesAttributeStatement(attributeAssertions, attributeKey);
            }

            boolean attributeValueMatch = areAttributeValuesRegexes ? valueMatchesRegex(attribute.getValue(), attributeValues) : attributeValues.contains(attribute.getValue());
            if (!attributeValueMatch) {
                return false;
            }
        }

        return true;
    }

    private List<Object> appliesAttributeStatement(Set<AttributeStatementType> attributeAssertions, String attributeKey) {
        return attributeAssertions.stream()
                .flatMap(statements -> statements.getAttributes().stream()
                        .map(choice -> choice.getAttribute()))
                .filter(attribute -> attributeKey.equals(attribute.getName())
                        || attributeKey.equals(attribute.getFriendlyName()))
                // Several statements with same name are treated like one with several values
                .flatMap(attribute -> attribute.getAttributeValue().stream())
                .collect(Collectors.toList());
    }

    private List<Object> appliesXacmlResource(Set<XacmlResourceType> xacmlResourceTypes, String attributeKey) {
        return xacmlResourceTypes.stream()
                .flatMap(resourceType -> resourceType.getAttributes().stream())
                .filter(attribute -> attributeKey.equals(attribute.getName())
                        || attributeKey.equals(attribute.getFriendlyName()))
                // Several statements with same name are treated like one with several values
                .flatMap(attribute -> attribute.getAttributeValue().stream())
                .collect(Collectors.toList());
    }
}
