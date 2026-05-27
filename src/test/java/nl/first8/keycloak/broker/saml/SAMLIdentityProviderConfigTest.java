package nl.first8.keycloak.broker.saml;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.MethodSource;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.function.BiConsumer;
import java.util.function.Function;
import java.util.function.Predicate;
import java.util.stream.Stream;

import static nl.first8.keycloak.broker.saml.SAMLIdentityProviderConfig.*;
import static org.junit.jupiter.api.Assertions.*;

class SAMLIdentityProviderConfigTest {

    private SAMLIdentityProviderConfig config;

    @BeforeEach
    void setUp() {
        config = new SAMLIdentityProviderConfig();
    }

    // -------------------------------------------------------------------------
    // artifactBindingResponse (existing tests kept as-is)
    // -------------------------------------------------------------------------

    @Test
    void artifactBindingResponseConstantHasExpectedKey() {
        assertEquals("artifactBindingResponse", ARTIFACT_BINDING_RESPONSE);
    }

    @Test
    void isArtifactBindingResponseReturnsFalseWhenNotSet() {
        assertFalse(config.isArtifactBindingResponse());
    }

    @Test
    void setArtifactBindingResponseTrueStoresStringInConfigMap() {
        config.setArtifactBindingResponse(true);

        assertEquals("true", config.getConfig().get(ARTIFACT_BINDING_RESPONSE));
    }

    @Test
    void setArtifactBindingResponseFalseStoresStringInConfigMap() {
        config.setArtifactBindingResponse(false);

        assertEquals("false", config.getConfig().get(ARTIFACT_BINDING_RESPONSE));
    }

    @Test
    void isArtifactBindingResponseReturnsTrueAfterSetTrue() {
        config.setArtifactBindingResponse(true);

        assertTrue(config.isArtifactBindingResponse());
    }

    @Test
    void isArtifactBindingResponseReturnsFalseAfterSetFalse() {
        config.setArtifactBindingResponse(true);
        config.setArtifactBindingResponse(false);

        assertFalse(config.isArtifactBindingResponse());
    }

    // -------------------------------------------------------------------------
    // Group 1: simple boolean properties (parameterized)
    // -------------------------------------------------------------------------

    record BooleanProperty(
        String key,
        BiConsumer<SAMLIdentityProviderConfig, Boolean> setter,
        Predicate<SAMLIdentityProviderConfig> getter
    ) {}

    static Stream<BooleanProperty> booleanProperties() {
        return Stream.of(
            new BooleanProperty(ARTIFACT_RESOLUTION,
                SAMLIdentityProviderConfig::setArtifactResolution,
                SAMLIdentityProviderConfig::isArtifactResolution),
            new BooleanProperty(ARTIFACT_RESOLUTION_WITH_XML_HEADER,
                SAMLIdentityProviderConfig::setArtifactResolutionWithXmlHeader,
                SAMLIdentityProviderConfig::isArtifactResolutionWithXmlHeader),
            new BooleanProperty(ARTIFACT_RESOLUTION_SERVICE_METADATA,
                SAMLIdentityProviderConfig::setIncludeArtifactResolutionServiceMetadata,
                SAMLIdentityProviderConfig::isIncludeArtifactResolutionServiceMetadata),
            new BooleanProperty(ARTIFACT_RESOLUTION_SOAP,
                SAMLIdentityProviderConfig::setArtifactResolutionSOAP,
                SAMLIdentityProviderConfig::isArtifactResolutionSOAP),
            new BooleanProperty(SIGN_ARTIFACT_RESOLUTION_REQUEST,
                SAMLIdentityProviderConfig::setSignArtifactResolutionRequest,
                SAMLIdentityProviderConfig::isSignArtifactResolutionRequest),
            new BooleanProperty(ARTIFACT_RESOLUTION_MUTUAL_TLS,
                SAMLIdentityProviderConfig::setMutualTls,
                SAMLIdentityProviderConfig::isMutualTLS),
            new BooleanProperty(SIGN_SP_METADATA,
                SAMLIdentityProviderConfig::setSignSpMetadata,
                SAMLIdentityProviderConfig::isSignSpMetadata),
            new BooleanProperty(ALLOW_CREATE,
                SAMLIdentityProviderConfig::setAllowCreated,
                SAMLIdentityProviderConfig::isAllowCreate)
        );
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("booleanProperties")
    void booleanPropertyDefaultsFalse(BooleanProperty prop) {
        assertFalse(prop.getter().test(config));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("booleanProperties")
    void booleanPropertySetTrueRoundTrips(BooleanProperty prop) {
        prop.setter().accept(config, true);

        assertTrue(prop.getter().test(config));
        assertEquals("true", config.getConfig().get(prop.key()));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("booleanProperties")
    void booleanPropertySetFalseRoundTrips(BooleanProperty prop) {
        prop.setter().accept(config, true);
        prop.setter().accept(config, false);

        assertFalse(prop.getter().test(config));
        assertEquals("false", config.getConfig().get(prop.key()));
    }

    // -------------------------------------------------------------------------
    // Group 2: useMetadataDescriptorUrl (special: false/null removes key)
    // -------------------------------------------------------------------------

    @Test
    void setUseMetadataDescriptorUrlTrueStoresKeyAndGetterReturnsTrue() {
        config.setUseMetadataDescriptorUrl(true);

        assertTrue(config.isUseMetadataDescriptorUrl());
        assertEquals("true", config.getConfig().get(USE_METADATA_DESCRIPTOR_URL));
    }

    @Test
    void setUseMetadataDescriptorUrlFalseRemovesKey() {
        config.setUseMetadataDescriptorUrl(true);
        config.setUseMetadataDescriptorUrl(false);

        assertFalse(config.isUseMetadataDescriptorUrl());
        assertFalse(config.getConfig().containsKey(USE_METADATA_DESCRIPTOR_URL));
    }

    @Test
    void setUseMetadataDescriptorUrlNullRemovesKey() {
        config.setUseMetadataDescriptorUrl(true);
        config.setUseMetadataDescriptorUrl(null);

        assertFalse(config.isUseMetadataDescriptorUrl());
        assertFalse(config.getConfig().containsKey(USE_METADATA_DESCRIPTOR_URL));
    }

    // -------------------------------------------------------------------------
    // Group 3: simple string properties (parameterized)
    // -------------------------------------------------------------------------

    record StringProperty(
        String key,
        BiConsumer<SAMLIdentityProviderConfig, String> setter,
        Function<SAMLIdentityProviderConfig, String> getter
    ) {}

    static Stream<StringProperty> stringProperties() {
        return Stream.of(
            new StringProperty(ARTIFACT_RESOLUTION_ENDPOINT,
                SAMLIdentityProviderConfig::setArtifactResolutionEndpoint,
                SAMLIdentityProviderConfig::getArtifactResolutionEndpoint),
            new StringProperty(AUTHN_REQUEST_SCOPING,
                SAMLIdentityProviderConfig::setScoping,
                SAMLIdentityProviderConfig::getScoping),
            new StringProperty(ATTRIBUTE_CONSUMING_SERVICE_NAME,
                SAMLIdentityProviderConfig::setAttributeConsumingServiceName,
                SAMLIdentityProviderConfig::getAttributeConsumingServiceName),
            new StringProperty(ATTRIBUTE_CONSUMING_SERVICE_METADATA,
                SAMLIdentityProviderConfig::setAttributeConsumingServiceMetadata,
                SAMLIdentityProviderConfig::getAttributeConsumingService)
        );
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("stringProperties")
    void stringPropertyDefaultsNull(StringProperty prop) {
        assertNull(prop.getter().apply(config));
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("stringProperties")
    void stringPropertyRoundTrips(StringProperty prop) {
        prop.setter().accept(config, "test-value");

        assertEquals("test-value", prop.getter().apply(config));
        assertEquals("test-value", config.getConfig().get(prop.key()));
    }

    // -------------------------------------------------------------------------
    // Group 4: charSet
    // -------------------------------------------------------------------------

    @Test
    void getCharSetReturnsUtf8WhenNotSet() {
        assertEquals(StandardCharsets.UTF_8, config.getCharSet());
    }

    @Test
    void setCharSetRoundTrips() {
        config.setCharSet("ISO-8859-1");

        assertEquals(Charset.forName("ISO-8859-1"), config.getCharSet());
    }

    // -------------------------------------------------------------------------
    // Group 5: assertionConsumingServiceIndex
    // -------------------------------------------------------------------------

    @Test
    void getAssertionConsumingServiceIndexReturnsNullWhenNotSet() {
        assertNull(config.getAssertionConsumingServiceIndex());
    }

    @Test
    void setAssertionConsumingServiceIndexRoundTrips() {
        config.setAssertionConsumingServiceIndex(5);

        assertEquals(5, config.getAssertionConsumingServiceIndex());
        assertEquals("5", config.getConfig().get(ASSERTION_CONSUMING_SERVICE_INDEX));
    }

    // -------------------------------------------------------------------------
    // Group 6: metadataValidUntilUnit and metadataValidUntilPeriod
    // NOTE: setMetadataValidUntilPeriod writes to METADATA_VALID_UNTIL_UNIT (wrong key)
    //       — the failing test below documents this bug pending a fix.
    // -------------------------------------------------------------------------

    @Test
    void getMetadataValidUntilUnitReturnsNullWhenNotSet() {
        assertNull(config.getMetadataValidUntilUnit());
    }

    @Test
    void setMetadataValidUntilUnitRoundTrips() {
        config.setMetadataValidUntilUnit(3);

        assertEquals(3, config.getMetadataValidUntilUnit());
        assertEquals("3", config.getConfig().get(METADATA_VALID_UNTIL_UNIT));
    }

    @Test
    void getMetadataValidUntilPeriodReturnsNullWhenNotSet() {
        assertNull(config.getMetadataValidUntilPeriod());
    }

    @Test
        // BUG: setMetadataValidUntilPeriod stores under METADATA_VALID_UNTIL_UNIT instead of METADATA_VALID_UNTIL_PERIOD
    void setMetadataValidUntilPeriodRoundTrips() {
        config.setMetadataValidUntilPeriod(7);

        assertEquals(7, config.getMetadataValidUntilPeriod());
        assertEquals("7", config.getConfig().get(METADATA_VALID_UNTIL_PERIOD));
    }

    // -------------------------------------------------------------------------
    // Group 7: attributeConsumingServiceIndex (special: negative/null removes key)
    // -------------------------------------------------------------------------

    @Test
    void getAttributeConsumingServiceIndexReturnsNullWhenNotSet() {
        assertNull(config.getAttributeConsumingServiceIndex());
    }

    @Test
    void setAttributeConsumingServiceIndexPositiveRoundTrips() {
        config.setAttributeConsumingServiceIndex(3);

        assertEquals(3, config.getAttributeConsumingServiceIndex());
        assertEquals("3", config.getConfig().get(ATTRIBUTE_CONSUMING_SERVICE_INDEX));
    }

    @Test
    void setAttributeConsumingServiceIndexZeroRoundTrips() {
        config.setAttributeConsumingServiceIndex(0);

        assertEquals(0, config.getAttributeConsumingServiceIndex());
    }

    @Test
    void setAttributeConsumingServiceIndexNegativeRemovesKeyAndReturnsNull() {
        config.setAttributeConsumingServiceIndex(3);
        config.setAttributeConsumingServiceIndex(-1);

        assertNull(config.getAttributeConsumingServiceIndex());
        assertFalse(config.getConfig().containsKey(ATTRIBUTE_CONSUMING_SERVICE_INDEX));
    }

    @Test
    void setAttributeConsumingServiceIndexNullRemovesKeyAndReturnsNull() {
        config.setAttributeConsumingServiceIndex(3);
        config.setAttributeConsumingServiceIndex(null);

        assertNull(config.getAttributeConsumingServiceIndex());
        assertFalse(config.getConfig().containsKey(ATTRIBUTE_CONSUMING_SERVICE_INDEX));
    }

    // -------------------------------------------------------------------------
    // Group 8: linkedProviders
    // -------------------------------------------------------------------------

    @Test
    void getLinkedProvidersReturnsEmptyListWhenNotSet() {
        assertTrue(config.getLinkedProviders().isEmpty());
    }

    @Test
    void setLinkedProvidersRoundTrips() {
        config.setLinkedProviders("provider1");

        assertEquals(java.util.List.of("provider1"), config.getLinkedProviders());
    }

    @Test
    void setLinkedProvidersNullReturnsEmptyList() {
        config.setLinkedProviders(null);

        assertTrue(config.getLinkedProviders().isEmpty());
    }
}
