package nl.first8.keycloak.broker.saml;

import nl.first8.keycloak.dom.saml.v2.assertion.AssertionType;
import nl.first8.keycloak.dom.saml.v2.metadata.RequestedAttributeValueType;
import nl.first8.keycloak.dom.saml.v2.protocol.ResponseType;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.dom.saml.v2.assertion.AuthnStatementType;
import org.keycloak.dom.saml.v2.protocol.ArtifactResponseType;
import org.keycloak.dom.saml.v2.protocol.StatusCodeType;
import org.keycloak.dom.saml.v2.protocol.StatusType;
import org.mockito.InjectMocks;
import org.mockito.MockitoAnnotations;


import javax.xml.datatype.XMLGregorianCalendar;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;

class SAMLDataMarshallerTest {

    @InjectMocks
    private SAMLDataMarshaller dataMarshaller;

    @BeforeEach
    public void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void shouldDeserializeImmutableCollectionsListCorrectly() throws ClassNotFoundException {
        SAMLDataMarshaller marshaller = new SAMLDataMarshaller();

        Class<?> immutableListClass = Class.forName("java.util.ImmutableCollections$List12");

        Object result = marshaller.deserialize("WyI4ODcyMzMxMyJd", immutableListClass);

        assertInstanceOf(List.class, result, "Deserialized object should be a List.");

        assertNotNull(result, "Deserialized result should not be null.");
        assertEquals(1, ((List<?>) result).size(), "List should contain one element.");

        assertEquals("88723313", ((List<?>) result).get(0), "List should contain the expected element.");
    }

    @Test
    void testSerializeResponseType() {
        ResponseType responseType = new ResponseType("abc", mock(XMLGregorianCalendar.class));
        StatusType statusType = new StatusType();
        statusType.setStatusCode(new StatusCodeType());
        responseType.setStatus(statusType);

        String result = dataMarshaller.serialize(responseType);
        String expectedXml = "<samlp:Response xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"abc\" Version=\"2.0\" IssueInstant=\"Mock for XMLGregorianCalendar, hashCode: .+\"><samlp:Status><samlp:StatusCode></samlp:StatusCode></samlp:Status></samlp:Response>";

        assertNotNull(result);
        assertTrue(result.matches(expectedXml));
    }

    @Test
    void testSerializeAssertionType() {
        AssertionType assertionType = new AssertionType("abc", mock(XMLGregorianCalendar.class));

        String result = dataMarshaller.serialize(assertionType);
        String expectedXml = "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"abc\" Version=\"2.0\" IssueInstant=\"Mock for XMLGregorianCalendar, hashCode: .+\"></saml:Assertion>";

        assertNotNull(result);
        assertTrue(result.matches(expectedXml));
    }

    @Test
    void testSerializeAuthStatementType() {
        AuthnStatementType authnStatementType = new AuthnStatementType(mock(XMLGregorianCalendar.class));

        String result = dataMarshaller.serialize(authnStatementType);
        String expectedXml = "<saml:AuthnStatement xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\" AuthnInstant=\"Mock for XMLGregorianCalendar, hashCode: .+\"></saml:AuthnStatement>";

        assertNotNull(result);
        assertTrue(result.matches(expectedXml));
    }

    @Test
    void testSerializeArtifactResponseType() {
        ArtifactResponseType artifactResponseType = new ArtifactResponseType("abc", mock(XMLGregorianCalendar.class));

        String result = dataMarshaller.serialize(artifactResponseType);
        String expectedXml = "<samlp:ArtifactResponse xmlns:samlp=\"urn:oasis:names:tc:SAML:2.0:protocol\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"abc\" Version=\"2.0\" IssueInstant=\"Mock for XMLGregorianCalendar, hashCode: .+\"></samlp:ArtifactResponse>";

        assertNotNull(result);
        assertTrue(result.matches(expectedXml));
    }

    @Test
    void testSerializeUnknownObjectType() {
        RequestedAttributeValueType unknownObject = new RequestedAttributeValueType("testname");

        assertThrows(IllegalArgumentException.class, () -> {
            dataMarshaller.serialize(unknownObject);
        });
    }
}
