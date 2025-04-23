package nl.first8.keycloak.saml.processing.core.parsers.saml.assertion;

import nl.first8.keycloak.dom.saml.v2.assertion.AttributeStatementType;
import nl.first8.keycloak.dom.saml.v2.assertion.AttributeStatementType.ASTChoiceType;
import org.keycloak.saml.common.exceptions.ParsingException;
import org.keycloak.saml.common.util.StaxParserUtil;

import javax.xml.stream.XMLEventReader;
import javax.xml.stream.events.StartElement;

/**
 * Parse the <conditions> in the saml assertion
 *
 * @since Oct 14, 2010
 */
public class SAMLAttributeStatementParser extends AbstractStaxSamlAssertionParser<AttributeStatementType> {

    private static final SAMLAttributeStatementParser INSTANCE = new SAMLAttributeStatementParser();

    private SAMLAttributeStatementParser() {
        super(SAMLAssertionQNames.ATTRIBUTE_STATEMENT);
    }

    public static SAMLAttributeStatementParser getInstance() {
        return INSTANCE;
    }

    @Override
    protected AttributeStatementType instantiateElement(XMLEventReader xmlEventReader, StartElement element) throws ParsingException {
        return new AttributeStatementType();
    }

    @Override
    protected void processSubElement(XMLEventReader xmlEventReader, AttributeStatementType target, SAMLAssertionQNames element, StartElement elementDetail) throws ParsingException {
        switch (element) {
            case ATTRIBUTE:
                target.addAttribute(new ASTChoiceType(SAMLAttributeParser.getInstance().parse(xmlEventReader)));
                break;
            case ENCRYPTED_ATTRIBUTE:
                target.addEncryptedAttribute(SAMLEncryptedAttributeParser.getInstance().parse(xmlEventReader));
                break;

            default:
                throw LOGGER.parserUnknownTag(StaxParserUtil.getElementName(elementDetail), elementDetail.getLocation());
        }
    }
}