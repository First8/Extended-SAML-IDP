package nl.first8.keycloak.saml;

import nl.first8.keycloak.dom.saml.v2.metadata.EntityDescriptorType;
import nl.first8.keycloak.dom.saml.v2.metadata.SPSSODescriptorType;
import org.jboss.logging.Logger;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.keycloak.dom.saml.v2.metadata.EndpointType;
import org.keycloak.dom.saml.v2.metadata.IndexedEndpointType;
import org.keycloak.dom.saml.v2.metadata.KeyDescriptorType;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;


import javax.xml.datatype.XMLGregorianCalendar;
import java.net.URI;
import java.util.*;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class SPMetadataDescriptorBuilderTest {

    private SPMetadataDescriptorBuilder builder;

    @Mock
    private Logger logger; // Mock logger

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
        builder = new SPMetadataDescriptorBuilder();

        SPMetadataDescriptorBuilder.logger = logger;

        // Configure builder with valid values
        builder.entityId("test-entity")
                .loginBinding(URI.create("https://example.com/login"))
                .logoutBinding(URI.create("https://example.com/logout"))
                .artifactResolutionBinding(URI.create("https://example.com/artifact"))
                .assertionEndpoints(List.of(URI.create("https://example.com/assert")))
                .artifactResolutionEndpoint(URI.create("https://example.com/artifact-resolution"))
                .logoutEndpoints(List.of(URI.create("https://example.com/logout")))
                .wantAuthnRequestsSigned(true)
                .wantAssertionsSigned(true)
                .wantAssertionsEncrypted(false)
                .nameIDPolicyFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress")
                .signingCerts(List.of(new KeyDescriptorType()))
                .encryptionCerts(List.of(new KeyDescriptorType()))
                .metadataValidUntilUnit(Calendar.DAY_OF_MONTH)
                .metadataValidUntilPeriod(7)
                .defaultAssertionEndpoint(1);
    }

    @Test
    void testBuild_ValidEntityDescriptor() {
        EntityDescriptorType entityDescriptor = builder.build();

        assertNotNull(entityDescriptor);
        assertEquals("test-entity", entityDescriptor.getEntityID());
        assertNotNull(entityDescriptor.getID());

        // Validate 'validUntil' field
        XMLGregorianCalendar validUntil = entityDescriptor.getValidUntil();
        assertNotNull(validUntil);

        // Ensure at least one choice type exists
        assertFalse(entityDescriptor.getChoiceType().isEmpty());

        // Verify logging behavior
        verify(logger).info("Building SP Entity Descriptor");
    }

    @Test
    void shouldSetSigningCerts() {
        KeyDescriptorType keyDescriptor = new KeyDescriptorType();
        List<KeyDescriptorType> signingCerts = Collections.singletonList(keyDescriptor);

        EntityDescriptorType entityDescriptor = builder
                .signingCerts(signingCerts)
                .wantAuthnRequestsSigned(true)
                .entityId("https://test-sp.example.com")
                .build();

        assertNotNull(entityDescriptor);
        assertFalse(entityDescriptor.getChoiceType().isEmpty());

        // Extract the SPSSODescriptor and check if the signing key is added
        SPSSODescriptorType spSSODescriptor = entityDescriptor.getChoiceType().get(0)
                .getDescriptors().get(0)
                .getSpDescriptor();

        assertNotNull(spSSODescriptor);
        assertTrue(spSSODescriptor.getKeyDescriptor().size() == 1);
    }

    @Test
    void shouldSetLogoutEndpoints() throws Exception {
        List<URI> logoutEndpoints = List.of(
                new URI("https://test-sp.example.com/logout1"),
                new URI("https://test-sp.example.com/logout2")
        );

        URI logoutBinding = new URI("https://test-sp.example.com/logout-binding");

        EntityDescriptorType entityDescriptor = builder
                .logoutEndpoints(logoutEndpoints)
                .logoutBinding(logoutBinding)
                .entityId("https://test-sp.example.com")
                .build();

        SPSSODescriptorType spSSODescriptor = entityDescriptor.getChoiceType().get(0)
                .getDescriptors().get(0).getSpDescriptor();

        assertEquals(logoutEndpoints.size(), spSSODescriptor.getSingleLogoutService().size());

        for (int i = 0; i < logoutEndpoints.size(); i++) {
            EndpointType endpoint = spSSODescriptor.getSingleLogoutService().get(i);
            assertEquals(logoutBinding, endpoint.getBinding());
            assertEquals(logoutEndpoints.get(i), endpoint.getLocation());
        }
    }

    @Test
    void shouldSetArtifactResolutionService() throws Exception {
        URI artifactResolutionEndpoint = new URI("https://test-sp.example.com/artifact");
        URI artifactResolutionBinding = new URI("https://test-sp.example.com/artifact-binding");

        EntityDescriptorType entityDescriptor = builder
                .artifactResolutionEndpoint(artifactResolutionEndpoint)
                .artifactResolutionBinding(artifactResolutionBinding)
                .entityId("https://test-sp.example.com")
                .build();

        SPSSODescriptorType spSSODescriptor = entityDescriptor.getChoiceType().get(0)
                .getDescriptors().get(0)
                .getSpDescriptor();

        assertEquals(1, spSSODescriptor.getArtifactResolutionService().size());

        IndexedEndpointType indexedEndpoint = spSSODescriptor.getArtifactResolutionService().get(0);
        assertEquals(artifactResolutionBinding, indexedEndpoint.getBinding());
        assertEquals(artifactResolutionEndpoint, indexedEndpoint.getLocation());
        assertEquals(0, indexedEndpoint.getIndex());
    }

    @Test
    void shouldSetAssertionConsumerServicesCorrectly() throws Exception {
        List<URI> assertionEndpoints = List.of(
                new URI("https://test-sp.example.com/assertion1"),
                new URI("https://test-sp.example.com/assertion2")
        );

        URI loginBinding = new URI("https://test-sp.example.com/login-binding");
        int defaultAssertionIndex = 2;

        EntityDescriptorType entityDescriptor = builder
                .assertionEndpoints(assertionEndpoints)
                .defaultAssertionEndpoint(defaultAssertionIndex)
                .loginBinding(loginBinding)
                .entityId("https://test-sp.example.com")
                .build();

        SPSSODescriptorType spSSODescriptor = entityDescriptor.getChoiceType().get(0)
                .getDescriptors().get(0)
                .getSpDescriptor();

        int expectedServices = assertionEndpoints.size() * 2; // Each assertion endpoint gets two bindings
        assertEquals(expectedServices, spSSODescriptor.getAssertionConsumerService().size());

        int assertionIndex = 1;
        for (URI assertionEndpoint : assertionEndpoints) {
            IndexedEndpointType httpPostEndpoint = spSSODescriptor.getAssertionConsumerService().get(assertionIndex - 1);
            assertEquals(loginBinding, httpPostEndpoint.getBinding());
            assertEquals(assertionEndpoint, httpPostEndpoint.getLocation());
            assertEquals(assertionIndex, httpPostEndpoint.getIndex());
            assertEquals(assertionIndex == defaultAssertionIndex, httpPostEndpoint.isIsDefault());

            IndexedEndpointType artifactBindingEndpoint = spSSODescriptor.getAssertionConsumerService().get(assertionIndex);
            assertEquals(JBossSAMLURIConstants.SAML_HTTP_ARTIFACT_BINDING.getUri(), artifactBindingEndpoint.getBinding());
            assertEquals(assertionEndpoint, artifactBindingEndpoint.getLocation());
            assertEquals(assertionIndex + 1, artifactBindingEndpoint.getIndex());
            assertEquals((assertionIndex + 1) == defaultAssertionIndex, artifactBindingEndpoint.isIsDefault());

            assertionIndex += 2;
        }
    }

    @Test
    void shouldSetMetadataValidUntil() {
        int metadataValidUntilUnit = 10;
        int metadataValidUntilPeriod = Calendar.YEAR;

        EntityDescriptorType entityDescriptor = builder
                .metadataValidUntilUnit(metadataValidUntilUnit)
                .metadataValidUntilPeriod(metadataValidUntilPeriod)
                .entityId("https://test-sp.example.com")
                .build();

        XMLGregorianCalendar validUntil = entityDescriptor.getValidUntil();
        assertNotNull(validUntil);

        Calendar expectedCalendar = Calendar.getInstance();
        expectedCalendar.add(metadataValidUntilPeriod, metadataValidUntilUnit);

        Calendar actualCalendar = validUntil.toGregorianCalendar();
        assertEquals(expectedCalendar.get(Calendar.YEAR), actualCalendar.get(Calendar.YEAR));
        assertEquals(expectedCalendar.get(Calendar.MONTH), actualCalendar.get(Calendar.MONTH));
        assertEquals(expectedCalendar.get(Calendar.DAY_OF_MONTH), actualCalendar.get(Calendar.DAY_OF_MONTH));
    }
}


