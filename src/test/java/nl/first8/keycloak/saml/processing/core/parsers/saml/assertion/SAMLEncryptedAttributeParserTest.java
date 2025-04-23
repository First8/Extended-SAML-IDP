package nl.first8.keycloak.saml.processing.core.parsers.saml.assertion;

import nl.first8.keycloak.dom.saml.v2.assertion.SAMLEncryptedAttribute;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import javax.xml.stream.XMLInputFactory;
import javax.xml.stream.XMLEventReader;
import javax.xml.stream.events.StartElement;
import java.io.StringReader;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class SAMLEncryptedAttributeParserTest {

    private SAMLEncryptedAttributeParser parser;

    @BeforeEach
    void setUp() {
        parser = SAMLEncryptedAttributeParser.getInstance();
    }

    @Test
    void testInstantiateElement() throws Exception {
        XMLEventReader xmlEventReader = mock(XMLEventReader.class);
        StartElement startElement = mock(StartElement.class);

        SAMLEncryptedAttribute result = parser.instantiateElement(xmlEventReader, startElement);

        assertNotNull(result, "Parsed object should not be null");
    }

    @Test
    void testParseRealSAML() throws Exception {
        // Sample SAML Encrypted Attribute XML
        String samlXml = "<saml:EncryptedAttribute xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\">" +
                "<xenc:EncryptedData xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\">" +
                "<xenc:CipherData>" +
                "<xenc:CipherValue>EncryptedDataHere</xenc:CipherValue>" +
                "</xenc:CipherData>" +
                "</xenc:EncryptedData>" +
                "<xenc:EncryptedKey xmlns:xenc=\"http://www.w3.org/2001/04/xmlenc#\" Id=\"key123\" Recipient=\"testRecipient\">" +
                "<xenc:CipherData>" +
                "<xenc:CipherValue>EncryptedKeyHere</xenc:CipherValue>" +
                "</xenc:CipherData>" +
                "</xenc:EncryptedKey>" +
                "</saml:EncryptedAttribute>";


        // Create XML Event Reader from the string
        XMLInputFactory factory = XMLInputFactory.newInstance();
        XMLEventReader xmlEventReader = factory.createXMLEventReader(new StringReader(samlXml));

        // Move to the first StartElement
        while (xmlEventReader.hasNext()) {
            if (xmlEventReader.peek().isStartElement()) {
                break;
            }
            xmlEventReader.nextEvent();
        }

        // Parse the SAML Encrypted Attribute
        SAMLEncryptedAttribute result = parser.parse(xmlEventReader);

        // Validate results
        assertNotNull(result, "Parsed result should not be null");
        assertNotNull(result.getEncryptedData(), "EncryptedData should be parsed");
        assertEquals(1, result.getEncryptedKeys().size(), "Should contain one EncryptedKey");

        assertEquals("testRecipient", result.getEncryptedKeys().get(0).getRecipient());
        assertEquals("key123", result.getEncryptedKeys().get(0).getId());
    }
}

