package nl.first8.saml.util;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;
import java.util.UUID;
import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.common.SAMLObject;
import org.opensaml.saml.common.SignableSAMLObject;
import org.opensaml.saml.saml2.core.ArtifactResponse;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.AttributeValue;
import org.opensaml.saml.saml2.core.Audience;
import org.opensaml.saml.saml2.core.AudienceRestriction;
import org.opensaml.saml.saml2.core.AuthnContext;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.EncryptedAttribute;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.impl.ArtifactResponseBuilder;
import org.opensaml.saml.saml2.core.impl.AssertionBuilder;
import org.opensaml.saml.saml2.core.impl.AttributeBuilder;
import org.opensaml.saml.saml2.core.impl.AttributeStatementBuilder;
import org.opensaml.saml.saml2.core.impl.AttributeValueBuilder;
import org.opensaml.saml.saml2.core.impl.AudienceBuilder;
import org.opensaml.saml.saml2.core.impl.AudienceRestrictionBuilder;
import org.opensaml.saml.saml2.core.impl.AuthnContextBuilder;
import org.opensaml.saml.saml2.core.impl.AuthnContextClassRefBuilder;
import org.opensaml.saml.saml2.core.impl.AuthnStatementBuilder;
import org.opensaml.saml.saml2.core.impl.ConditionsBuilder;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml.saml2.core.impl.NameIDBuilder;
import org.opensaml.saml.saml2.core.impl.ResponseBuilder;
import org.opensaml.saml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.saml.saml2.core.impl.SubjectBuilder;
import org.opensaml.saml.saml2.encryption.Encrypter;
import org.opensaml.security.credential.BasicCredential;
import org.opensaml.security.credential.Credential;
import org.opensaml.xmlsec.config.impl.DefaultSecurityConfigurationBootstrap;
import org.opensaml.xmlsec.encryption.support.DataEncryptionParameters;
import org.opensaml.xmlsec.encryption.support.EncryptionConstants;
import org.opensaml.xmlsec.encryption.support.EncryptionException;
import org.opensaml.xmlsec.encryption.support.KeyEncryptionParameters;
import org.opensaml.xmlsec.keyinfo.KeyInfoGenerator;
import org.opensaml.xmlsec.keyinfo.NamedKeyInfoGeneratorManager;
import org.opensaml.xmlsec.signature.Signature;
import org.opensaml.xmlsec.signature.impl.SignatureBuilder;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.Signer;
import org.w3c.dom.Element;

public class SAMLUtil {

    /**
     * Shared RSA key pair for all test signing and encryption. Static so every test method
     * sees the same public key - the config stubs and the SAML builders must agree on it.
     */
    public static final KeyPair TEST_KEY_PAIR;

    // OpenSAML's XML provider registry must be bootstrapped before any builder or marshaller
    // lookup. TEST_KEY_PAIR is generated once here to avoid repeated RSA keygen across tests
    // and to keep the public key material stable for the config stubs that reference it.
    static {
        try {
            InitializationService.initialize();
        } catch (InitializationException e) {
            throw new ExceptionInInitializerError(e);
        }
        KeyPair kp;
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            kp = kpg.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("Failed to generate test RSA key pair", e);
        }
        TEST_KEY_PAIR = kp;
    }

    /**
     * Builds the ArtifactResponse object graph. Delegates to createResponse() for the inner
     * Response so signature and conditions are consistent between the two levels.
     */
    public static ArtifactResponse createArtifactResponse() throws SignatureException, MarshallingException, EncryptionException {
        return createArtifactResponse(createResponse());
    }

    private static ArtifactResponse createArtifactResponse(Response response) throws SignatureException, MarshallingException {
        return createArtifactResponse(response, createBasicCredential());
    }

    private static ArtifactResponse createArtifactResponse(Response response, Credential credential) throws SignatureException, MarshallingException {
        Signature signature = createSignature(credential);
        ArtifactResponse artifactResponse = new ArtifactResponseBuilder().buildObject();
        artifactResponse.setSchemaLocation("http://www.w3.org/2001/XMLSchema");
        artifactResponse.setID("_" + UUID.randomUUID());
        artifactResponse.setIssueInstant(Instant.now());
        artifactResponse.setInResponseTo("ID_" + UUID.randomUUID());
        artifactResponse.setIssuer(createIssuer());
        artifactResponse.setStatus(createStatus());
        artifactResponse.setMessage(response);
        artifactResponse.setSignature(signature);
        marshall(artifactResponse, signature);
        return artifactResponse;
    }

    /**
     * Happy-path fixture: a fully signed ArtifactResponse wrapping a valid Response.
     * Returned by the resolveArtifact stub in testHandleSamlResponse.
     */
    public static String createArtifactResponseAsString() throws MarshallingException, SignatureException, EncryptionException {
        ArtifactResponse artifactResponse = createArtifactResponse();

        return prettyPrint(artifactResponse.getDOM());
    }


    /**
     * Builds a valid assertion with eHerkenning-style attributes. One attribute (ActingSubjectID)
     * is encrypted in the fixture builder - SAMLEndpoint passes it through raw, decryption is
     * UserEncryptedAttributeMapper's job, not tested here.
     */
    private static Assertion createAssertion() throws MarshallingException, SignatureException, EncryptionException {
        return createAssertion(createConditions(), createSignature());
    }

    /**
     * Signs the assertion with the given credential instead of TEST_KEY_PAIR - used when
     * building a response signed with a wrong key so the full chain uses the same bad key.
     */
    private static Assertion createAssertion(Credential credential) throws MarshallingException, SignatureException, EncryptionException {
        return createAssertion(createConditions(), createSignature(credential));
    }

    private static Assertion createAssertion(Conditions conditions) throws MarshallingException, SignatureException, EncryptionException {
        return createAssertion(conditions, createSignature());
    }

    private static Assertion createAssertion(Conditions conditions, Signature signature) throws MarshallingException, SignatureException, EncryptionException {
        Assertion assertion = new AssertionBuilder().buildObject();
        assertion.setID("_" + UUID.randomUUID());
        assertion.setIssueInstant(Instant.now());
        assertion.setIssuer(createIssuer());
        assertion.setSubject(createSubject());
        assertion.setConditions(conditions);
        assertion.getAuthnStatements().add(createAuthnStatement());
        assertion.getAttributeStatements().add(createAttributeStatements());
        assertion.setSignature(signature);
        marshall(assertion, signature);
        return assertion;
    }

    /**
     * eHerkenning attribute set: ServiceID and ServiceUUID are plaintext; ActingSubjectID is
     * encrypted (AES-128 / RSA-OAEP) here in the fixture builder. SAMLEndpoint passes it
     * through raw - decryption is UserEncryptedAttributeMapper's job, not tested here.
     */
    private static AttributeStatement createAttributeStatements() throws EncryptionException {
        AttributeStatement attributeStatement = new AttributeStatementBuilder().buildObject();
        attributeStatement.getAttributes().add(createAttribute("urn:etoegang:core:ServiceID", "urn:etoegang:DV:00000001812483297000:services:1"));
        attributeStatement.getAttributes().add(createAttribute("urn:etoegang:core:ServiceUUID", "95df68ac-301c-40e7-a14b-0fb495e004a4"));
        attributeStatement.getEncryptedAttributes().add(createEncryptedAttribute("urn:etoegang:core:ActingSubjectID", "173599916"));
        return attributeStatement;
    }

    private static EncryptedAttribute createEncryptedAttribute(String name, String value) throws EncryptionException {
        Attribute attribute = createAttribute(name, value);
        return getEncrypter().encrypt(attribute);
    }

    /**
     * Configures AES-128 data encryption with RSA-OAEP key transport against TEST_KEY_PAIR.
     * PEER placement embeds the encrypted key inside EncryptedData, which is what SAMLEndpoint
     * expects when decrypting attributes.
     */
    private static Encrypter getEncrypter() {
        Credential credential = createBasicCredential();

        DataEncryptionParameters encParams = new DataEncryptionParameters();
        encParams.setAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES128);

        NamedKeyInfoGeneratorManager manager = DefaultSecurityConfigurationBootstrap
            .buildBasicKeyInfoGeneratorManager();

        KeyEncryptionParameters kekParams = new KeyEncryptionParameters();
        kekParams.setEncryptionCredential(credential);
        kekParams.setAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP);
        KeyInfoGenerator keyInfoGenerator = manager.getDefaultManager().getFactory(credential).newInstance();
        kekParams.setKeyInfoGenerator(keyInfoGenerator);

        Encrypter samlEncrypter = new Encrypter(encParams, kekParams);
        samlEncrypter.setKeyPlacement(Encrypter.KeyPlacement.PEER);
        return samlEncrypter;
    }

    private static Attribute createAttribute(String name, String value) {
        Attribute attribute = new AttributeBuilder().buildObject();
        attribute.setName(name);
        attribute.setSchemaLocation("http://www.w3.org/2001/XMLSchema-instance");
        attribute.getAttributeValues().add(createAttributeValue(value));
        return attribute;
    }

    private static AttributeValue createAttributeValue(String text) {
        AttributeValue attributeValue = new AttributeValueBuilder().buildObject();
        attributeValue.setTextContent(text);
        return attributeValue;
    }

    private static AuthnStatement createAuthnStatement() {
        AuthnStatement authnStatement = new AuthnStatementBuilder().buildObject();
        authnStatement.setAuthnInstant(Instant.now());
        authnStatement.setAuthnContext(createAuthnContext());
        return authnStatement;
    }

    private static AuthnContext createAuthnContext() {
        AuthnContext authnContext = new AuthnContextBuilder().buildObject();
        authnContext.setAuthnContextClassRef(createAuthnContextClassRef());
        return authnContext;
    }

    private static AuthnContextClassRef createAuthnContextClassRef() {
        AuthnContextClassRef authnContextClassRef = new AuthnContextClassRefBuilder().buildObject();
        authnContextClassRef.setValue("urn:etoegang:core:assurance-class:loa3");
        return authnContextClassRef;
    }

    /**
     * Valid time window: -1 min to +5 min, with an audience restriction pointing at the
     * test ACS URL. The 15-second clock skew configured in getMockConfig() has no effect here.
     */
    private static Conditions createConditions() {
        Conditions conditions = new ConditionsBuilder().buildObject();
        Instant now = Instant.now();
        conditions.setNotBefore(now.minus(1, ChronoUnit.MINUTES));
        conditions.setNotOnOrAfter(now.plus(5, ChronoUnit.MINUTES));
        conditions.getAudienceRestrictions().add(createAudienceRestriction());
        return conditions;
    }

    /**
     * Expired time window: -10 min to -5 min. ConditionsValidator will reject any assertion
     * carrying these conditions, even within the allowed clock skew.
     */
    private static Conditions createConditionsExpired() {
        Conditions conditions = new ConditionsBuilder().buildObject();
        Instant now = Instant.now();
        conditions.setNotBefore(now.minus(10, ChronoUnit.MINUTES));
        conditions.setNotOnOrAfter(now.minus(5, ChronoUnit.MINUTES));
        conditions.getAudienceRestrictions().add(createAudienceRestriction());
        return conditions;
    }

    /**
     * Like createAssertion() but uses an expired Conditions window - used to build the
     * fixture returned by createArtifactResponseWithExpiredAssertionAsString().
     */
    private static Assertion createAssertionExpired() throws MarshallingException, SignatureException, EncryptionException {
        return createAssertion(createConditionsExpired());
    }

    /**
     * Fixture for the expired-assertion test. The inner assertion's Conditions window is
     * entirely in the past (NotOnOrAfter = now - 5 min) so ConditionsValidator rejects it.
     */
    public static String createArtifactResponseWithExpiredAssertionAsString() throws MarshallingException, SignatureException, EncryptionException {
        return prettyPrint(createArtifactResponse(createResponse(createAssertionExpired())).getDOM());
    }

    private static AudienceRestriction createAudienceRestriction() {
        AudienceRestriction audienceRestriction = new AudienceRestrictionBuilder().buildObject();
        audienceRestriction.getAudiences().add(createAudience());
        return audienceRestriction;
    }

    /**
     * Audience URI must match the base URI returned by getMockKeycloakSession() (https://auth.testhost.lcl)
     * so ConditionsValidator's audience restriction check passes in the happy-path test.
     */
    private static Audience createAudience() {
        Audience audience = new AudienceBuilder().buildObject();
        audience.setValue("https://auth.testhost.lcl/realms/test-realm/broker/saml-extended/endpoint");
        return audience;
    }

    private static Subject createSubject() {
        Subject subject = new SubjectBuilder().buildObject();
        subject.setNameID(createNameId());
        return subject;
    }

    /**
     * The NameID value "9170bd..." is the subject identity extracted by SAMLEndpoint and
     * asserted on in testHandleSamlResponse (identity.getId() and identity.getBrokerUserId()).
     */
    private static NameID createNameId() {
        NameID nameID = new NameIDBuilder().buildObject();
        nameID.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:transient");
        nameID.setNameQualifier("urn:etoegang:MR:00000003271247010000:entities:9113");
        nameID.setValue("9170bd139d9b5e364290187482329e89bcb431ea");
        return nameID;
    }

    /**
     * Wraps TEST_KEY_PAIR as an OpenSAML BasicCredential for use in signing and encryption.
     */
    private static Credential createBasicCredential() {
        return new BasicCredential(TEST_KEY_PAIR.getPublic(), TEST_KEY_PAIR.getPrivate());
    }

    public static String createResponseAsString() throws SignatureException, MarshallingException, EncryptionException {
        Response response = createResponse();
        return prettyPrint(response.getDOM());
    }

    public static Response createResponse() throws SignatureException, MarshallingException, EncryptionException {
        return createResponse(createAssertion());
    }

    private static Response createResponse(Assertion assertion) throws SignatureException, MarshallingException {
        return createResponse(assertion, createBasicCredential());
    }

    private static Response createResponse(Assertion assertion, Credential credential) throws SignatureException, MarshallingException {
        Response response = new ResponseBuilder().buildObject();
        response.setDestination("https://auth.testhost.lcl/realms/test-realm/broker/saml-extended/endpoint");
        response.setID("_" + UUID.randomUUID());
        response.setInResponseTo("ID_" + UUID.randomUUID());
        response.setIssueInstant(Instant.now());
        response.setIssuer(createIssuer());
        response.setStatus(createStatus());
        response.getAssertions().add(assertion);
        Signature signature = createSignature(credential);
        response.setSignature(signature);
        marshall(response, signature);
        return response;
    }

    private static Issuer createIssuer() {
        Issuer issuer = new IssuerBuilder().buildObject();
        issuer.setNoNamespaceSchemaLocation("urn:oasis:names:tc:SAML:2.0:assertion");
        issuer.setValue("urn:etoegang:HM:00000003271247010000:entities:9113");

        return issuer;
    }

    public static Signature createSignature() {
        return createSignature(createBasicCredential());
    }

    /**
     * Core signature factory: RSA-SHA256 with exclusive C14N. Algorithm choices must match
     * what Keycloak's signature validator accepts.
     */
    private static Signature createSignature(Credential credential) {
        Signature signature = new SignatureBuilder().buildObject();
        signature.setSigningCredential(credential);
        signature.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        return signature;
    }

    /**
     * Fixture for the wrong-signature test. Generates a fresh key pair that is
     * NOT TEST_KEY_PAIR, then signs the entire response tree with it.
     *
     * The config stub supplies TEST_KEY_PAIR's public cert as the trusted key,
     * so signature validation must fail.
     */
    public static String createArtifactResponseSignedWithWrongKeyAsString() throws MarshallingException, SignatureException, EncryptionException {
        KeyPair wrongKeyPair;
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
            kpg.initialize(2048);
            wrongKeyPair = kpg.generateKeyPair();
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e); // RSA is always available
        }
        Credential wrongCredential = new BasicCredential(wrongKeyPair.getPublic(), wrongKeyPair.getPrivate());
        Assertion assertion = createAssertion(wrongCredential);

        Response response = createResponse(assertion, wrongCredential);
        ArtifactResponse artifactResponse = createArtifactResponse(response, wrongCredential);
        return prettyPrint(artifactResponse.getDOM());
    }

    /**
     * Wraps TEST_KEY_PAIR.getPublic() in a self-signed X.509 cert and returns it Base64-
     * encoded. Used by getMockConfigWithSignatureValidation() as the trusted signing cert,
     * so signature validation succeeds for TEST_KEY_PAIR-signed responses and fails for others.
     */
    public static String getCorrectPublicKeyCertificateAsBase64() throws OperatorCreationException, CertificateException {
        X500Name subject = new X500Name("CN=test");
        Date notBefore = new Date(System.currentTimeMillis() - 86_400_000L);
        Date notAfter = new Date(System.currentTimeMillis() + 86_400_000L * 365);

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
            subject, BigInteger.ONE, notBefore, notAfter, subject, TEST_KEY_PAIR.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(TEST_KEY_PAIR.getPrivate());
        X509Certificate cert = new JcaX509CertificateConverter().getCertificate(builder.build(signer));

        return Base64.getEncoder().encodeToString(cert.getEncoded());
    }

    private static Status createStatus() {
        Status status = new StatusBuilder().buildObject();
        status.setStatusCode(createStatusCode());

        return status;
    }

    private static StatusCode createStatusCode() {
        StatusCode statusCode = new StatusCodeBuilder().buildObject();
        statusCode.setValue("urn:oasis:names:tc:SAML:2.0:status:Success");

        return statusCode;
    }

    private static String prettyPrint(Element element) throws MarshallingException, SignatureException {
        return SerializeSupport.prettyPrintXML(element);
    }

    /**
     * Marshals the object to DOM first, then signs. The two steps must stay in this order:
     * OpenSAML computes the signature over the canonical XML, which only exists after marshalling.
     */
    private static Element marshall(SAMLObject object, Signature signature) throws MarshallingException, SignatureException {
        Marshaller out = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(object);
        out.marshall(object);
        Element element = object.getDOM();

        if (object instanceof SignableSAMLObject) {
            Signer.signObject(signature);
        }
        return element;
    }

}
