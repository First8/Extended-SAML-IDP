package nl.first8.keycloak.saml.processing.core.parsers.saml.assertion;

import nl.first8.keycloak.dom.saml.v2.assertion.AssertionType;
import org.keycloak.saml.common.ErrorCodes;
import org.keycloak.saml.common.exceptions.ParsingException;
import org.keycloak.saml.common.util.StaxParserUtil;
import org.keycloak.saml.processing.core.parsers.saml.assertion.SAMLAuthnStatementParser;
import org.keycloak.saml.processing.core.parsers.saml.assertion.SAMLConditionsParser;
import org.keycloak.saml.processing.core.parsers.saml.assertion.SAMLSubjectParser;
import org.keycloak.saml.processing.core.parsers.util.SAMLParserUtil;
import org.keycloak.saml.processing.core.saml.v2.util.XMLTimeUtil;

import javax.xml.datatype.XMLGregorianCalendar;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.events.StartElement;

public class SAMLAssertionParser extends AbstractStaxSamlAssertionParser<AssertionType> {

    private static final String VERSION_2_0 = "2.0";

    private static final SAMLAssertionParser INSTANCE = new SAMLAssertionParser();

    private SAMLAssertionParser() {
        super(SAMLAssertionQNames.ASSERTION);
    }

    public static SAMLAssertionParser getInstance() {
        return INSTANCE;
    }

    @Override
    protected AssertionType instantiateElement(XMLEventReader xmlEventReader, StartElement nextElement) throws ParsingException {
        SAMLParserUtil.validateAttributeValue(nextElement, SAMLAssertionQNames.ATTR_VERSION, VERSION_2_0);
        String id = StaxParserUtil.getRequiredAttributeValue(nextElement, SAMLAssertionQNames.ATTR_ID);
        XMLGregorianCalendar issueInstant = XMLTimeUtil.parse(StaxParserUtil.getRequiredAttributeValue(nextElement, SAMLAssertionQNames.ATTR_ISSUE_INSTANT));

        return new AssertionType(id, issueInstant);
    }

    @Override
    protected void processSubElement(XMLEventReader xmlEventReader, AssertionType target, SAMLAssertionQNames element, StartElement elementDetail) throws ParsingException {
        switch (element) {
            case ISSUER:
                target.setIssuer(SAMLParserUtil.parseNameIDType(xmlEventReader));
                break;

            case SIGNATURE:
                target.setSignature(StaxParserUtil.getDOMElement(xmlEventReader));
                break;

            case SUBJECT:
                target.setSubject(SAMLSubjectParser.getInstance().parse(xmlEventReader));
                break;

            case CONDITIONS:
                target.setConditions(SAMLConditionsParser.getInstance().parse(xmlEventReader));
                break;

            case ADVICE:
                target.addXacmlResources(new SAMLAdviceParser().processSubElement(xmlEventReader));
                break;

            case STATEMENT:
                elementDetail = StaxParserUtil.getNextStartElement(xmlEventReader);
                String xsiTypeValue = StaxParserUtil.getXSITypeValue(elementDetail);
                throw new RuntimeException(ErrorCodes.UNKNOWN_XSI + xsiTypeValue);

            case AUTHN_STATEMENT:
                target.addStatement(SAMLAuthnStatementParser.getInstance().parse(xmlEventReader));
                break;

            case AUTHZ_DECISION_STATEMENT:
                StaxParserUtil.bypassElementBlock(xmlEventReader);
                // Ignored
                break;

            case ATTRIBUTE_STATEMENT:
                target.addStatement(SAMLAttributeStatementParser.getInstance().parse(xmlEventReader));
                break;

            default:
                throw LOGGER.parserUnknownTag(StaxParserUtil.getElementName(elementDetail), elementDetail.getLocation());
        }
    }
}