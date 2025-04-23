package nl.first8.keycloak.broker.saml;

import nl.first8.keycloak.dom.saml.v2.assertion.AssertionType;
import nl.first8.keycloak.dom.saml.v2.protocol.ResponseType;
import nl.first8.keycloak.saml.common.constants.GeneralConstants;
import nl.first8.keycloak.saml.processing.core.saml.v2.writers.SAMLAssertionWriter;
import nl.first8.keycloak.saml.processing.core.saml.v2.writers.SAMLResponseWriter;
import nl.first8.keycloak.saml.processing.core.parsers.saml.SAMLParser;
import org.jboss.logging.Logger;
import org.keycloak.broker.provider.DefaultDataMarshaller;
import org.keycloak.dom.saml.v2.assertion.AuthnStatementType;
import org.keycloak.dom.saml.v2.protocol.ArtifactResponseType;
import org.keycloak.saml.common.exceptions.ParsingException;
import org.keycloak.saml.common.exceptions.ProcessingException;
import org.keycloak.saml.common.util.StaxUtil;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.util.List;

public class SAMLDataMarshaller extends DefaultDataMarshaller {
    protected static final Logger logger = Logger.getLogger(SAMLDataMarshaller.class);

    @Override
    public String serialize(Object obj) {

        if (isKnownClassType(obj.getClass().getName())) {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();

            try {
                if (obj instanceof ResponseType) {
                    ResponseType responseType = (ResponseType) obj;
                    SAMLResponseWriter samlWriter = new SAMLResponseWriter(StaxUtil.getXMLStreamWriter(bos));
                    samlWriter.write(responseType);
                } else if (obj instanceof AssertionType) {
                    AssertionType assertion = (AssertionType) obj;
                    SAMLAssertionWriter samlWriter = new SAMLAssertionWriter(StaxUtil.getXMLStreamWriter(bos));
                    samlWriter.write(assertion);
                } else if (obj instanceof AuthnStatementType) {
                    AuthnStatementType authnStatement = (AuthnStatementType) obj;
                    SAMLAssertionWriter samlWriter = new SAMLAssertionWriter(StaxUtil.getXMLStreamWriter(bos));
                    samlWriter.write(authnStatement, true);
                } else if (obj instanceof ArtifactResponseType) {
                    ArtifactResponseType artifactResponseType = (ArtifactResponseType) obj;
                    SAMLResponseWriter samlWriter = new SAMLResponseWriter(StaxUtil.getXMLStreamWriter(bos));
                    samlWriter.write(artifactResponseType);
                } else {
                    throw new IllegalArgumentException("Do not yet know how to serialize object of type " + obj.getClass().getName());
                }
            } catch (ProcessingException pe) {
                throw new RuntimeException(pe);
            }

            return new String(bos.toByteArray(), GeneralConstants.SAML_CHARSET);
        } else {
            return super.serialize(obj);
        }
    }

    @Override
    public <T> T deserialize(String serialized, Class<T> clazz) {
        if (isKnownClassType(clazz.getName())) {
            String xmlString = serialized;

            try {
                if (clazz.equals(ResponseType.class) || clazz.equals(AssertionType.class) || clazz.equals(AuthnStatementType.class) || clazz.equals(ArtifactResponseType.class)) {
                    byte[] bytes = xmlString.getBytes(GeneralConstants.SAML_CHARSET);
                    InputStream is = new ByteArrayInputStream(bytes);
                    Object respType = SAMLParser.getInstance().parse(is);
                    return clazz.cast(respType);
                } else {
                    logger.errorf("Do not yet know how to deserialize object of type %s", clazz.getName());
                    throw new IllegalArgumentException("Do not yet know how to deserialize object of type " + clazz.getName());
                }
            } catch (ParsingException pe) {
                throw new RuntimeException(pe);
            }

        } else {
            if (List.class.isAssignableFrom(clazz) && clazz.getName().startsWith("java.util.ImmutableCollections")) {
                try {
                    logger.tracef("Deserializing Immutable List (class: %s) from String: %s", clazz.getName(), serialized);
                    return (T) super.deserialize(serialized, List.class);
                } catch (ClassCastException e) {
                    logger.error("Error deserializing Immutable List from String", e);
                    throw new RuntimeException("Error deserializing Immutable List", e);
                }
            }
            logger.tracef("Deserializing (unknown) class (%s) from String: %s", clazz.getName(), serialized);
            return super.deserialize(serialized, clazz);
        }
    }

    private boolean isKnownClassType(String className) {
        boolean isKnown = className.startsWith("nl.first8.keycloak.dom.saml") || className.startsWith("org.keycloak.dom.saml");
        logger.tracef("%s is %sa known class.", className, (isKnown?"":"not "));
        return isKnown;
    }

}
