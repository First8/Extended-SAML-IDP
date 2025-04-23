package nl.first8.keycloak.saml.processing.core.parsers.saml.assertion;

import nl.first8.keycloak.dom.saml.v2.assertion.SamlEncryptedId;
import nl.first8.keycloak.saml.processing.core.parsers.saml.xmlsec.EncryptedDataParser;
import nl.first8.keycloak.saml.processing.core.parsers.saml.xmlsec.EncryptedKeyParser;
import org.keycloak.dom.xmlsec.w3.xmlenc.EncryptedKeyType;
import org.keycloak.saml.common.exceptions.ParsingException;
import org.keycloak.saml.common.util.StaxParserUtil;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.events.Attribute;
import javax.xml.stream.events.StartElement;

public class SamlEncryptedIdParser extends AbstractStaxSamlAssertionParser<SamlEncryptedId> {

    private static final SamlEncryptedIdParser INSTANCE = new SamlEncryptedIdParser(SAMLAssertionQNames.ENCRYPTED_ID);

    public SamlEncryptedIdParser(SAMLAssertionQNames expectedStartElement) {
        super(expectedStartElement);
    }

    public static SamlEncryptedIdParser getInstance() {
        return INSTANCE;
    }

    @Override
    protected SamlEncryptedId instantiateElement(XMLEventReader xmlEventReader, StartElement startElement) throws ParsingException {
        return new SamlEncryptedId();
    }

    @Override
    protected void processSubElement(XMLEventReader xmlEventReader, SamlEncryptedId target, SAMLAssertionQNames element, StartElement elementDetail) throws ParsingException {
        switch (element) {
            case ENCRYPTED_DATA:
                target.setEncryptedData(EncryptedDataParser.getInstance().parse(xmlEventReader));
                break;
            case ENCRYPTED_KEY:
                EncryptedKeyType encryptedKey = EncryptedKeyParser.getInstance().parse(xmlEventReader);
                encryptedKey.setId(elementDetail.getAttributeByName(QName.valueOf("Id")).getValue());
                Attribute recipient = elementDetail.getAttributeByName(QName.valueOf("Recipient"));
                if(recipient != null)
                    encryptedKey.setRecipient(recipient.getValue());
                target.addEncryptedKey(encryptedKey);
                break;

            default:
                throw LOGGER.parserUnknownTag(StaxParserUtil.getElementName(elementDetail), elementDetail.getLocation());
        }
    }
}
