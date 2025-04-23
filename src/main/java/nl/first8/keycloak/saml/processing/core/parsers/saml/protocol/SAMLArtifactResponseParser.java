package nl.first8.keycloak.saml.processing.core.parsers.saml.protocol;

import org.keycloak.dom.saml.v2.protocol.ArtifactResponseType;
import org.keycloak.saml.common.exceptions.ParsingException;
import org.keycloak.saml.common.util.StaxParserUtil;
import org.keycloak.saml.processing.core.parsers.saml.protocol.*;
import org.keycloak.saml.processing.core.parsers.util.SAMLParserUtil;
import org.keycloak.saml.processing.core.saml.v2.util.XMLTimeUtil;
import org.w3c.dom.Element;

import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.events.StartElement;

public class SAMLArtifactResponseParser extends SAMLStatusResponseTypeParser<ArtifactResponseType> {

    private static final SAMLArtifactResponseParser INSTANCE = new SAMLArtifactResponseParser();

    private SAMLArtifactResponseParser() {
        super(SAMLProtocolQNames.ARTIFACT_RESPONSE);
    }

    public static SAMLArtifactResponseParser getInstance() {
        return INSTANCE;
    }

    @Override
    protected ArtifactResponseType instantiateElement(XMLEventReader xmlEventReader, StartElement element) throws ParsingException {
        SAMLParserUtil.validateAttributeValue(element, SAMLProtocolQNames.ATTR_VERSION, VERSION_2_0);
        String id = StaxParserUtil.getRequiredAttributeValue(element, SAMLProtocolQNames.ATTR_ID);
        XMLGregorianCalendar issueInstant = XMLTimeUtil.parse(StaxParserUtil.getRequiredAttributeValue(element, SAMLProtocolQNames.ATTR_ISSUE_INSTANT));

        ArtifactResponseType res = new ArtifactResponseType(id, issueInstant);

        // Let us set the attributes
        super.parseBaseAttributes(element, res);

        return res;
    }

    @Override
    protected void processSubElement(XMLEventReader xmlEventReader, ArtifactResponseType target, SAMLProtocolQNames element, StartElement elementDetail) throws ParsingException {
        switch (element) {
            case ISSUER:
                target.setIssuer(SAMLParserUtil.parseNameIDType(xmlEventReader));
                break;

            case SIGNATURE:
                Element sig = StaxParserUtil.getDOMElement(xmlEventReader);
                target.setSignature(sig);
                break;

            case EXTENSIONS:
                SAMLExtensionsParser extensionsParser = SAMLExtensionsParser.getInstance();
                target.setExtensions(extensionsParser.parse(xmlEventReader));
                break;

            case AUTHN_REQUEST:
                SAMLAuthNRequestParser authnParser = SAMLAuthNRequestParser.getInstance();
                target.setAny(authnParser.parse(xmlEventReader));
                break;

            case RESPONSE:
                SAMLResponseParser responseParser = SAMLResponseParser.getInstance();
                target.setAny(responseParser.parse(xmlEventReader));
                break;

            case STATUS:
                target.setStatus(SAMLStatusParser.getInstance().parse(xmlEventReader));
                break;

            case LOGOUT_REQUEST:
                SAMLSloRequestParser sloRequestParser = SAMLSloRequestParser.getInstance();
                target.setAny(sloRequestParser.parse(xmlEventReader));
                break;

            case LOGOUT_RESPONSE:
                SAMLSloResponseParser sloResponseParser = SAMLSloResponseParser.getInstance();
                target.setAny(sloResponseParser.parse(xmlEventReader));
                break;

            default:
                throw LOGGER.parserUnknownTag(StaxParserUtil.getElementName(elementDetail), elementDetail.getLocation());
        }
    }
}