package nl.first8.keycloak.broker.saml.mappers;

import nl.first8.keycloak.broker.saml.SAMLEndpoint;
import nl.first8.keycloak.broker.saml.SAMLIdentityProviderFactory;
import nl.first8.keycloak.dom.saml.v2.assertion.AssertionType;
import nl.first8.keycloak.dom.saml.v2.assertion.AttributeStatementType;
import nl.first8.keycloak.dom.saml.v2.assertion.SamlEncryptedId;
import nl.first8.keycloak.saml.encryption.DecryptionException;
import nl.first8.keycloak.saml.encryption.SamlDecrypter;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.AbstractIdentityProviderMapper;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.crypto.Algorithm;
import org.keycloak.crypto.KeyUse;
import org.keycloak.crypto.KeyWrapper;
import org.keycloak.dom.saml.v2.assertion.AttributeType;
import org.keycloak.dom.saml.v2.assertion.NameIDType;
import org.keycloak.dom.saml.v2.assertion.SubjectType;
import org.keycloak.models.*;
import org.keycloak.models.utils.KeycloakModelUtils;
import org.keycloak.provider.ProviderConfigProperty;

import java.security.PrivateKey;
import java.util.*;
import java.util.function.UnaryOperator;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class UsernameTemplateMapper extends AbstractIdentityProviderMapper {

    protected static final Logger logger = Logger.getLogger(UsernameTemplateMapper.class);

    public static final String[] COMPATIBLE_PROVIDERS = {SAMLIdentityProviderFactory.PROVIDER_ID};

    public static final String TEMPLATE = "template";
    public static final String TARGET = "target";

    public enum Target  {
        LOCAL              { public void set(BrokeredIdentityContext context, String value) { context.setModelUsername(value); } },
        BROKER_ID          { public void set(BrokeredIdentityContext context, String value) { context.setId(value); } },
        BROKER_USERNAME    { public void set(BrokeredIdentityContext context, String value) { context.setUsername(value); } };
        public abstract void set(BrokeredIdentityContext context, String value);
    }
    public static final List<String> TARGETS = Arrays.asList(UsernameTemplateMapper.Target.LOCAL.toString(), UsernameTemplateMapper.Target.BROKER_ID.toString(), UsernameTemplateMapper.Target.BROKER_USERNAME.toString());

    public static final Map<String, UnaryOperator<Object>> TRANSFORMERS = new HashMap<>();

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();
    private static final Set<IdentityProviderSyncMode> IDENTITY_PROVIDER_SYNC_MODES = new HashSet<>(Arrays.asList(IdentityProviderSyncMode.values()));

    private static KeyWrapper keys;

    static {
        ProviderConfigProperty property;
        property = new ProviderConfigProperty();
        property.setName(TEMPLATE);
        property.setLabel("Template");
        property.setHelpText("Template to use to format the username to import.  Substitutions are enclosed in ${}.  For example: '${ALIAS}.${NAMEID}'.  ALIAS is the provider alias.  NAMEID is that SAML name id assertion.  ATTRIBUTE.<NAME> references a SAML attribute where name is the attribute name or friendly name. \n"
          + "The substitution can be converted to upper or lower case by appending |uppercase or |lowercase to the substituted value, e.g. '${NAMEID | lowercase} \n"
          + "Local part of email can be extracted by appending |localpart to the substituted value, e.g. ${ATTRIBUTE.email | localpart}. If \"@\" is not part of the string, this conversion leaves the substitution untouched.");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setDefaultValue("${ALIAS}.${NAMEID}");
        configProperties.add(property);

        property = new ProviderConfigProperty();
        property.setName(TARGET);
        property.setLabel("Target");
        property.setHelpText("Destination field for the mapper. LOCAL (default) means that the changes are applied to the username stored in local database upon user import. BROKER_ID and BROKER_USERNAME means that the changes are stored into the ID or username used for federation user lookup, respectively.");
        property.setType(ProviderConfigProperty.LIST_TYPE);
        property.setOptions(TARGETS);
        property.setDefaultValue(UsernameTemplateMapper.Target.LOCAL.toString());
        configProperties.add(property);

        TRANSFORMERS.put("uppercase", UsernameTemplateMapper::toUpperCase);
        TRANSFORMERS.put("lowercase", UsernameTemplateMapper::toLowerCase);
        TRANSFORMERS.put("localpart", UsernameTemplateMapper::getEmailLocalPart);
        TRANSFORMERS.put("decrypt", UsernameTemplateMapper::decrypt);
    }

    public static final String PROVIDER_ID = "saml-extended-username-idp-mapper";

    public static String toUpperCase(Object input) {
        return ((String)input).toUpperCase();
    }

    public static String toLowerCase(Object input) {
        return ((String)input).toUpperCase();
    }

    public static String getEmailLocalPart(Object input) {
        String email = (String)input;
        int index = email == null ? -1 : email.lastIndexOf('@');
        if (index >= 0) {
            return email.substring(0, index).replace("mailto:","");
        } else {
            return email;
        }
    }

    public static String decrypt(Object attribute) {
        logger.debug("Decrypting string");
        try {
            if(attribute instanceof SamlEncryptedId) {
                NameIDType nameID = SamlDecrypter.decryptToNameID((SamlEncryptedId)attribute, (PrivateKey) keys.getPrivateKey());
                return nameID.getValue();
            } else {
                logger.warnf("Error parsing attribute `%s`, attribute is not of type SamlEncryptedId but `%s`.", attribute, attribute.getClass().getName());
            }
        } catch (DecryptionException e) {
            logger.errorf("Error decrypting attribute `%s`", attribute, e);
        }
        logger.warn("Decryption failed; returning toString value of object.");
        return attribute.toString();
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
        return "Preprocessor";
    }

    @Override
    public String getDisplayType() {
        return "Username Template Importer";
    }

    @Override
    public void updateBrokeredUserLegacy(KeycloakSession session, RealmModel realm, UserModel user, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
    }

    @Override
    public void updateBrokeredUser(KeycloakSession session, RealmModel realm, UserModel user, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        logger.info("Update Brokered User setting username from template");
        // preprocessFederatedIdentity gets called anyways, so we only need to set the username if necessary.
        // However, we don't want to set the username when the email is used as username
        if (getTarget(mapperModel.getConfig().get(TARGET)) == UsernameTemplateMapper.Target.LOCAL && !realm.isRegistrationEmailAsUsername()) {
            user.setUsername(context.getModelUsername());
        }
    }

    private static final Pattern SUBSTITUTION = Pattern.compile("\\$\\{([^}]+?)(?:\\s*\\|\\s*(\\S+)\\s*)?\\}");

    @Override
    public void preprocessFederatedIdentity(KeycloakSession session, RealmModel realm, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        logger.info("Preprocess Federated Identity setting username from template");
        keys = session.keys().getActiveKey(realm, KeyUse.SIG, Algorithm.RS256);
        setUserNameFromTemplate(mapperModel, context);
    }

    private void setUserNameFromTemplate(IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        AssertionType assertion = (AssertionType)context.getContextData().get(SAMLEndpoint.SAML_ASSERTION);
        String template = mapperModel.getConfig().get(TEMPLATE);
        logger.debugf("Searching for template: `%s`", template);
        Matcher m = SUBSTITUTION.matcher(template);
        StringBuffer sb = new StringBuffer();
        while (m.find()) {
            String variable = m.group(1).trim();
            String transformerKey = m.group(2);
            logger.debugf("Searching for transformer `%s`.", transformerKey);
            UnaryOperator<Object> transformer = Optional.ofNullable(transformerKey).map(TRANSFORMERS::get).orElse(UnaryOperator.identity());

            if (variable.equals("ALIAS")) {
                m.appendReplacement(sb, (String) transformer.apply(context.getIdpConfig().getAlias()));
            } else if (variable.equals("UUID")) {
                m.appendReplacement(sb, (String) transformer.apply(KeycloakModelUtils.generateId()));
            } else if (variable.equals("NAMEID")) {
                SubjectType subject = assertion.getSubject();
                SubjectType.STSubType subType = subject.getSubType();
                NameIDType subjectNameID = (NameIDType) subType.getBaseID();
                m.appendReplacement(sb, (String) transformer.apply(subjectNameID.getValue()));
            } else if (variable.startsWith("ATTRIBUTE.")) {
                String name = variable.substring("ATTRIBUTE.".length());
                Object value = null;
                for (AttributeStatementType statement : assertion.getAttributeStatements()) {
                    for (AttributeStatementType.ASTChoiceType choice : statement.getAttributes()) {
                        AttributeType attr = choice.getAttribute();
                        logger.tracef("Searching for `%s`, found: `%s` & `%s`", name, attr.getName(), attr.getFriendlyName());
                        if (name.equals(attr.getName()) || name.equals(attr.getFriendlyName())) {
                            List<Object> attributeValue = attr.getAttributeValue();
                            if (attributeValue != null && !attributeValue.isEmpty()) {
                                value = attributeValue.get(0);
                            }
                            break;
                        }
                    }
                }
                m.appendReplacement(sb, (String) transformer.apply(value));
            } else {
                m.appendReplacement(sb, m.group(1));
            }

        }
        m.appendTail(sb);

        UsernameTemplateMapper.Target t = getTarget(mapperModel.getConfig().get(TARGET));
        t.set(context, sb.toString());
    }

    @Override
    public String getHelpText() {
        return "Format the username to import.";
    }

    public static UsernameTemplateMapper.Target getTarget(String value) {
        try {
            return value == null ? UsernameTemplateMapper.Target.LOCAL : UsernameTemplateMapper.Target.valueOf(value);
        } catch (IllegalArgumentException ex) {
            return UsernameTemplateMapper.Target.LOCAL;
        }
    }

}

