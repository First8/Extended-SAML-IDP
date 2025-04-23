package nl.first8.keycloak.broker.saml.mappers;

import nl.first8.keycloak.dom.saml.v2.assertion.AssertionType;
import nl.first8.keycloak.dom.saml.v2.assertion.AttributeStatementType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.dom.saml.v2.assertion.AttributeType;
import org.keycloak.dom.saml.v2.assertion.NameIDType;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;
import org.keycloak.saml.processing.core.saml.v2.util.XMLTimeUtil;

import java.util.*;

import static org.mockito.Mockito.*;

class UserAttributeValueMapperTest {

    public static final String ATTRIBUTE_NAME = "urn:etoegang:core:LegalSubjectID";

    UserAttributeValueMapper mapper;

    @BeforeEach
    public void setUp() {
        this.mapper = new UserAttributeValueMapper();
    }

    @Test
    void preprocessFederatedIdentity_XmlElementAsBase64() {

        RealmModel realm = mock(RealmModel.class);

        KeycloakSession session = mock(KeycloakSession.class);

        IdentityProviderMapperModel mapperModel = mock(IdentityProviderMapperModel.class);
        Map<String, String> config = getConfig();
        when(mapperModel.getConfig()).thenReturn(config);

        BrokeredIdentityContext brokeredIdentityContext = mock(BrokeredIdentityContext.class);
        Map<String, Object> context = getContext();
        when(brokeredIdentityContext.getContextData()).thenReturn(context);

        mapper.preprocessFederatedIdentity(session, realm, mapperModel, brokeredIdentityContext);
    }

    private Map<String, Object> getContext() {

        String attributeValue = "<saml:EncryptedID xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" Id=\"_eafaac3107634baeb7a41b4131c440e5\" Type=\"http://www.w3.org/2001/04/xmlenc#Element\"><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#aes256-cbc\"/><ds:KeyInfo><ds:RetrievalMethod Type=\"http://www.w3.org/2001/04/xmlenc#EncryptedKey\" URI=\"#_c9034e8a48ac43dcbfcdef4ce0aec000\"/></ds:KeyInfo><xenc:CipherData><xenc:CipherValue> DFKsO9nqmQmi1cRiDHpY0kMSRLK8CFhdzX2pJh3gH5jgZPM3VS36AclLjLIIBvW2ln68qi5izMrcqIy5gWUqDxlrt5t7L5lSoppierATcxKHab9a0005FyYJl0kor9Z4TQouhr/bwZ2GBw4J88OiVwWrXWrjpqLIzbtJHiHsKkZ8Azh4FxR3xYlvFSdoJ3xHy4si2pQsCZ5KzGJislkNY/j/rKc2j2HX2aJXcJvJc0RvPqQT9yzKs3chJeSdujXaldK5FS/DBIkV0RMQ2nCzIpR+3pbxx+aMTmKx/YkvvhhEPi7xg5oXhOQ407LJCswHyjjj9Jx9274ocuaDNmdVAJyoMceL05awS5z/wLi8AyQ=</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData><xenc:EncryptedKey xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" Id=\"_c9034e8a48ac43dcbfcdef4ce0aec000\" Recipient=\"urn:etoegang:MR:0000000123456780000:entities:1234\"><xenc:EncryptionMethod Algorithm=\"http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p\"><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/></xenc:EncryptionMethod><ds:KeyInfo><ds:KeyName>43005cb6118b950cbc6664945cec888debc594a0</ds:KeyName></ds:KeyInfo><xenc:CipherData><xenc:CipherValue> MGn0l8bj2mZJIFY/HfXZs69JLOdmwqnogieizFdOtSFdnYYflcWZ8KIIm48/DkdXeYlmEPjWHNlwPWnTnN5HeZiUL8Oe3K/T+PTHxq1IFFY5sVDWcE6CgUR4RWZgvsX2Sru841gb1in7HEeOkyIV/hzojiqlbs/MCbD5z+yX5Z8Vo4gbsFVHOiZDOgmpWDUXsPonYn3EIPz8oOslrqgln6cuwCCFXEhRpT3vqMsey+V95EcJmLu9KMXYzdfvikm4cmzlDe9iLk15aeQza2xN+G1y3adov3TsrfbL2NBsK6CJ8U5h0M1QPicvgmFQFFKIdL6y/u9FuGGoq+Gn6P4VXg==</xenc:CipherValue></xenc:CipherData><xenc:ReferenceList><xenc:DataReference URI=\"#_eafaac3107634baeb7a41b4131c440e5\"/></xenc:ReferenceList></xenc:EncryptedKey></saml:EncryptedID>";

        List<Object> attributeValues = new ArrayList<>();
        attributeValues.add(attributeValue);

        AttributeType attributeType = mock(AttributeType.class);
        when(attributeType.getName()).thenReturn(ATTRIBUTE_NAME);
        when(attributeType.getAttributeValue()).thenReturn(attributeValues);

        AttributeStatementType.ASTChoiceType astChoiceType = mock(AttributeStatementType.ASTChoiceType.class);
        when(astChoiceType.getAttribute()).thenReturn(attributeType);

        List<AttributeStatementType.ASTChoiceType> astChoiceTypes = new ArrayList<>();
        astChoiceTypes.add(astChoiceType);

        AttributeStatementType attributeStatement = mock(AttributeStatementType.class);
        when(attributeStatement.getAttributes()).thenReturn(astChoiceTypes);

        Set<AttributeStatementType> attributeStatements = new HashSet<>();
        attributeStatements.add(attributeStatement);

        AssertionType assertionType = mock(AssertionType.class);
        when(assertionType.getID()).thenReturn("assertionTypeID");
        when(assertionType.getIssueInstant()).thenReturn(XMLTimeUtil.getIssueInstant());
        NameIDType nameIDType = new NameIDType();
        nameIDType.setValue("nameIdValue");
        nameIDType.setFormat(JBossSAMLURIConstants.NAMEID_FORMAT_PERSISTENT.getUri());
        when(assertionType.getIssuer()).thenReturn(nameIDType);
        when(assertionType.getSignature()).thenReturn(null);
        when(assertionType.getConditions()).thenReturn(null);
        when(assertionType.getSubject()).thenReturn(null);
        when(assertionType.getAdvice()).thenReturn(null);
        when(assertionType.getAttributeStatements()).thenReturn(attributeStatements);

        Map<String, Object> context = new HashMap<>();
        context.put("SAML_ASSERTION", assertionType);

        return context;
    }

    private Map<String, String> getConfig() {
        Map<String, String> config = new HashMap<>();
        config.put("user.attribute", "LegalSubjectID");
        config.put("attribute.name", ATTRIBUTE_NAME);
        config.put("attribute.decrypt", "false");
        config.put("attribute.xml.element", "true");

        return config;
    }
    
}