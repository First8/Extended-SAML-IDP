package nl.first8.keycloak.saml.processing;

import nl.first8.keycloak.saml.SAML2ArtifactResolutionBuilder;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.saml.common.util.DocumentUtil;
import org.w3c.dom.Document;

import static org.junit.jupiter.api.Assertions.*;

class SAML2ArtifactResolutionBuilderTest {

    private SAML2ArtifactResolutionBuilder builder;

    @BeforeEach
    void setUp() {
        builder = new SAML2ArtifactResolutionBuilder();
    }

    @Test
    void testToDocument_ValidInput_ShouldGenerateDocument() {
        // Arrange
        String testArtifact = "testArtifact123";
        String testIssuer = "testIssuer";

        builder.artifact(testArtifact).issuer(testIssuer);

        // Act
        Document document = builder.toDocument();

        // Assert
        assertNotNull(document, "Generated Document should not be null");
        String xmlString = DocumentUtil.asString(document);
        assertTrue(xmlString.contains(testArtifact), "Artifact should be present in the XML");
        assertTrue(xmlString.contains(testIssuer), "Issuer should be present in the XML");
    }
}

