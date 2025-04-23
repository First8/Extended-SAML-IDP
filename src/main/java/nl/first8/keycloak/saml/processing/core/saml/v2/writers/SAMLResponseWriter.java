package nl.first8.keycloak.saml.processing.core.saml.v2.writers;

import nl.first8.keycloak.dom.saml.v2.assertion.AssertionType;
import nl.first8.keycloak.dom.saml.v2.protocol.ResponseType;
import nl.first8.keycloak.saml.common.constants.JBossSAMLConstants;
import org.keycloak.dom.saml.v2.assertion.EncryptedAssertionType;
import org.keycloak.dom.saml.v2.assertion.NameIDType;
import org.keycloak.dom.saml.v2.protocol.*;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;
import org.keycloak.saml.common.exceptions.ProcessingException;
import org.keycloak.saml.common.util.StaxUtil;
import org.keycloak.saml.common.util.StringUtil;
import org.keycloak.saml.processing.core.saml.v2.writers.BaseWriter;
import org.w3c.dom.Element;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamWriter;
import java.net.URI;
import java.util.List;

import static org.keycloak.saml.common.constants.JBossSAMLURIConstants.PROTOCOL_NSURI;

public class SAMLResponseWriter extends BaseWriter {

    private final SAMLAssertionWriter assertionWriter;

    public SAMLResponseWriter(XMLStreamWriter writer) {
        super(writer);
        this.assertionWriter = new SAMLAssertionWriter(writer);
    }

    /**
     * Write a {@code ResponseType} to stream
     *
     * @param response
     * @param out
     *
     * @throws org.keycloak.saml.common.exceptions.ProcessingException
     */
    public void write(ResponseType response) throws ProcessingException {
        StaxUtil.writeStartElement(writer, PROTOCOL_PREFIX, JBossSAMLConstants.RESPONSE__PROTOCOL.get(), JBossSAMLURIConstants.PROTOCOL_NSURI.get());

        StaxUtil.writeNameSpace(writer, PROTOCOL_PREFIX, JBossSAMLURIConstants.PROTOCOL_NSURI.get());
        StaxUtil.writeNameSpace(writer, ASSERTION_PREFIX, JBossSAMLURIConstants.ASSERTION_NSURI.get());

        writeBaseAttributes(response);

        NameIDType issuer = response.getIssuer();
        if (issuer != null) {
            write(issuer, new QName(JBossSAMLURIConstants.ASSERTION_NSURI.get(), JBossSAMLConstants.ISSUER.get(), ASSERTION_PREFIX));
        }

        ExtensionsType extensions = response.getExtensions();
        if (extensions != null && extensions.getAny() != null && ! extensions.getAny().isEmpty()) {
            write(extensions);
        }

        StatusType status = response.getStatus();
        write(status);

        List<ResponseType.RTChoiceType> choiceTypes = response.getAssertions();
        if (choiceTypes != null) {
            for (ResponseType.RTChoiceType choiceType : choiceTypes) {
                AssertionType assertion = choiceType.getAssertion();
                if (assertion != null) {
                    assertionWriter.write(assertion);
                }

                EncryptedAssertionType encryptedAssertion = choiceType.getEncryptedAssertion();
                if (encryptedAssertion != null) {
                    Element encElement = encryptedAssertion.getEncryptedElement();
                    StaxUtil.writeDOMElement(writer, encElement);
                }
            }
        }
        StaxUtil.writeEndElement(writer);
        StaxUtil.flush(writer);
    }

    public void write(ArtifactResponseType response) throws ProcessingException {
        StaxUtil.writeStartElement(writer, PROTOCOL_PREFIX, JBossSAMLConstants.ARTIFACT_RESPONSE.get(), JBossSAMLURIConstants.PROTOCOL_NSURI.get());

        StaxUtil.writeNameSpace(writer, PROTOCOL_PREFIX, JBossSAMLURIConstants.PROTOCOL_NSURI.get());
        StaxUtil.writeNameSpace(writer, ASSERTION_PREFIX, JBossSAMLURIConstants.ASSERTION_NSURI.get());
        StaxUtil.writeDefaultNameSpace(writer, JBossSAMLURIConstants.ASSERTION_NSURI.get());

        writeBaseAttributes(response);

        NameIDType issuer = response.getIssuer();
        if (issuer != null) {
            write(issuer, new QName(JBossSAMLURIConstants.ASSERTION_NSURI.get(), JBossSAMLConstants.ISSUER.get(), ASSERTION_PREFIX));
        }

        Element sig = response.getSignature();
        if (sig != null) {
            StaxUtil.writeDOMElement(writer, sig);
        }
        ExtensionsType extensions = response.getExtensions();
        if (extensions != null && extensions.getAny() != null && ! extensions.getAny().isEmpty()) {
            write(extensions);
        }

        StatusType status = response.getStatus();
        if (status != null) {
            write(status);
        }
        Object anyObj = response.getAny();
        if (anyObj instanceof AuthnRequestType) {
            AuthnRequestType authn = (AuthnRequestType) anyObj;
            SAMLRequestWriter requestWriter = new SAMLRequestWriter(writer);
            requestWriter.write(authn);
        } else if (anyObj instanceof LogoutRequestType) {
            LogoutRequestType logoutRequestType = (LogoutRequestType) anyObj;
            SAMLRequestWriter requestWriter = new SAMLRequestWriter(writer);
            requestWriter.write(logoutRequestType);
        } else if (anyObj instanceof ResponseType) {
            ResponseType rt = (ResponseType) anyObj;
            write(rt);
        } else if (anyObj instanceof StatusResponseType) {
            StatusResponseType rt = (StatusResponseType) anyObj;
            write(rt, new QName(PROTOCOL_NSURI.get(), JBossSAMLConstants.LOGOUT_RESPONSE.get(), "samlp"));
        }

        StaxUtil.writeEndElement(writer);
        StaxUtil.flush(writer);
    }

    /**
     * Write a {@code StatusResponseType}
     *
     * @param response
     * @param qname QName of the starting element
     * @param out
     *
     * @throws ProcessingException
     */
    public void write(StatusResponseType response, QName qname) throws ProcessingException {
        if (qname == null) {
            StaxUtil.writeStartElement(writer, PROTOCOL_PREFIX, JBossSAMLConstants.STATUS_RESPONSE_TYPE.get(),
                    JBossSAMLURIConstants.PROTOCOL_NSURI.get());
        } else {
            StaxUtil.writeStartElement(writer, qname.getPrefix(), qname.getLocalPart(), qname.getNamespaceURI());
        }

        StaxUtil.writeNameSpace(writer, PROTOCOL_PREFIX, JBossSAMLURIConstants.PROTOCOL_NSURI.get());
        StaxUtil.writeNameSpace(writer, ASSERTION_PREFIX, JBossSAMLURIConstants.ASSERTION_NSURI.get());
        StaxUtil.writeDefaultNameSpace(writer, JBossSAMLURIConstants.ASSERTION_NSURI.get());

        writeBaseAttributes(response);

        NameIDType issuer = response.getIssuer();
        write(issuer, new QName(JBossSAMLURIConstants.ASSERTION_NSURI.get(), JBossSAMLConstants.ISSUER.get()));

        Element sig = response.getSignature();
        if (sig != null) {
            StaxUtil.writeDOMElement(writer, sig);
        }
        ExtensionsType extensions = response.getExtensions();
        if (extensions != null && extensions.getAny() != null && ! extensions.getAny().isEmpty()) {
            write(extensions);
        }

        StatusType status = response.getStatus();
        write(status);

        StaxUtil.writeEndElement(writer);
        StaxUtil.flush(writer);
    }

    /**
     * Write a {@code StatusType} to stream
     *
     * @param status
     * @param out
     *
     * @throws ProcessingException
     */
    public void write(StatusType status) throws ProcessingException {
        StaxUtil.writeStartElement(writer, PROTOCOL_PREFIX, JBossSAMLConstants.STATUS.get(), JBossSAMLURIConstants.PROTOCOL_NSURI.get());

        StatusCodeType statusCodeType = status.getStatusCode();
        write(statusCodeType);

        String statusMessage = status.getStatusMessage();
        if (StringUtil.isNotNull(statusMessage)) {
            StaxUtil.writeStartElement(writer, PROTOCOL_PREFIX, JBossSAMLConstants.STATUS_MESSAGE.get(), JBossSAMLURIConstants.PROTOCOL_NSURI.get());
            StaxUtil.writeEndElement(writer);
        }

        StatusDetailType statusDetail = status.getStatusDetail();
        if (statusDetail != null)
            write(statusDetail);

        StaxUtil.writeEndElement(writer);
        StaxUtil.flush(writer);
    }

    /**
     * Write a {@code StatusCodeType} to stream
     *
     * @param statusCodeType
     * @param out
     *
     * @throws ProcessingException
     */
    public void write(StatusCodeType statusCodeType) throws ProcessingException {
        StaxUtil.writeStartElement(writer, PROTOCOL_PREFIX, JBossSAMLConstants.STATUS_CODE.get(), JBossSAMLURIConstants.PROTOCOL_NSURI.get());

        URI value = statusCodeType.getValue();
        if (value != null) {
            StaxUtil.writeAttribute(writer, JBossSAMLConstants.VALUE.get(), value.toASCIIString());
        }
        StatusCodeType subStatusCode = statusCodeType.getStatusCode();
        if (subStatusCode != null)
            write(subStatusCode);

        StaxUtil.writeEndElement(writer);
        StaxUtil.flush(writer);
    }

    /**
     * Write a {@code StatusDetailType} to stream
     *
     * @param statusDetailType
     * @param out
     *
     * @throws ProcessingException
     */
    public void write(StatusDetailType statusDetailType) throws ProcessingException {
        StaxUtil.writeStartElement(writer, PROTOCOL_PREFIX, JBossSAMLConstants.STATUS_CODE.get(), JBossSAMLURIConstants.PROTOCOL_NSURI.get());
        StaxUtil.writeEndElement(writer);
        StaxUtil.flush(writer);
    }

    /**
     * Write the common attributes for all response types
     *
     * @param statusResponse
     *
     * @throws ProcessingException
     */
    private void writeBaseAttributes(StatusResponseType statusResponse) throws ProcessingException {
        // Attributes
        StaxUtil.writeAttribute(writer, JBossSAMLConstants.ID.get(), statusResponse.getID());
        StaxUtil.writeAttribute(writer, JBossSAMLConstants.VERSION.get(), statusResponse.getVersion());
        StaxUtil.writeAttribute(writer, JBossSAMLConstants.ISSUE_INSTANT.get(), statusResponse.getIssueInstant().toString());

        String destination = statusResponse.getDestination();
        if (StringUtil.isNotNull(destination))
            StaxUtil.writeAttribute(writer, JBossSAMLConstants.DESTINATION.get(), destination);

        String consent = statusResponse.getConsent();
        if (StringUtil.isNotNull(consent))
            StaxUtil.writeAttribute(writer, JBossSAMLConstants.CONSENT.get(), consent);

        String inResponseTo = statusResponse.getInResponseTo();
        if (StringUtil.isNotNull(inResponseTo))
            StaxUtil.writeAttribute(writer, JBossSAMLConstants.IN_RESPONSE_TO.get(), inResponseTo);
    }
}