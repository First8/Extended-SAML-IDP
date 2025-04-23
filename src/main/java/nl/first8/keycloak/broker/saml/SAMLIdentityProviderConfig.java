package nl.first8.keycloak.broker.saml;

import org.jboss.logging.Logger;
import org.keycloak.models.IdentityProviderModel;

import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.LinkedList;
import java.util.List;

public class SAMLIdentityProviderConfig extends org.keycloak.broker.saml.SAMLIdentityProviderConfig {
    protected static final Logger logger = Logger.getLogger(SAMLIdentityProviderConfig.class);

    public static final String ASSERTION_CONSUMING_SERVICE_INDEX = "assertionConsumingServiceIndex";
    public static final String ARTIFACT_RESOLUTION = "artifactResolution";
    public static final String ARTIFACT_RESOLUTION_ENDPOINT = "artifactResolutionEndpoint";
    public static final String SIGN_ARTIFACT_RESOLUTION_REQUEST = "signArtifactResolutionRequest";
    public static final String ARTIFACT_RESOLUTION_SOAP = "artifactResolutionSOAP";
    public static final String ARTIFACT_RESOLUTION_WITH_XML_HEADER = "artifactResolutionWithXmlHeader";
    public static final String ARTIFACT_RESOLUTION_SERVICE_METADATA = "includeArtifactResolutionServiceMetadata";
    public static final String CHAR_SET = "charSet";
    public static final String METADATA_VALID_UNTIL_UNIT = "metadataValidUntilUnit";
    public static final String METADATA_VALID_UNTIL_PERIOD = "metadataValidUntilPeriod";
    public static final String ARTIFACT_RESOLUTION_MUTUAL_TLS = "mutualTls";
    public static final String IGNORE_SAML_ADVICE_NODES = "ignoreSamlAdviceNodes";
    public static final String AUTHN_REQUEST_SCOPING = "scoping";
    public static final String LINKED_PROVIDERS = "linkedProviders";


    public SAMLIdentityProviderConfig() {
        super();
    }

    public SAMLIdentityProviderConfig(IdentityProviderModel identityProviderModel) {
        super(identityProviderModel);
    }

    public Integer getAssertionConsumingServiceIndex() {
        return getConfig().get(ASSERTION_CONSUMING_SERVICE_INDEX) != null ? Integer.parseInt(getConfig().get(ASSERTION_CONSUMING_SERVICE_INDEX)) : null;
    }

    public void setAssertionConsumingServiceIndex(int assertionConsumingServiceIndex) {
        getConfig().put(ASSERTION_CONSUMING_SERVICE_INDEX, String.valueOf(assertionConsumingServiceIndex));
    }


    public boolean isArtifactResolutionWithXmlHeader() {
        return Boolean.parseBoolean(getConfig().get(ARTIFACT_RESOLUTION_WITH_XML_HEADER));
    }

    public void setArtifactResolutionWithXmlHeader(boolean artifactResolutionWithXmlHeader) {
        getConfig().put(ARTIFACT_RESOLUTION_WITH_XML_HEADER, String.valueOf(artifactResolutionWithXmlHeader));
    }

    public boolean isArtifactResolution() {
        return Boolean.parseBoolean(getConfig().get(ARTIFACT_RESOLUTION));
    }

    public void setArtifactResolution(boolean artifactResolution) {
        getConfig().put(ARTIFACT_RESOLUTION, String.valueOf(artifactResolution));
    }

    public boolean isIncludeArtifactResolutionServiceMetadata() {
        return Boolean.parseBoolean(getConfig().get(ARTIFACT_RESOLUTION_SERVICE_METADATA));
    }

    public void setIncludeArtifactResolutionServiceMetadata(boolean includeArtifactResolutionServiceMetadata) {
        getConfig().put(ARTIFACT_RESOLUTION_SERVICE_METADATA, String.valueOf(includeArtifactResolutionServiceMetadata));
    }

    public boolean isArtifactResolutionSOAP() {
        return Boolean.parseBoolean(getConfig().get(ARTIFACT_RESOLUTION_SOAP));
    }

    public void setArtifactResolutionSOAP(boolean artifactResolutionSOAP) {
        getConfig().put(ARTIFACT_RESOLUTION_SOAP, String.valueOf(artifactResolutionSOAP));
    }

    public String getArtifactResolutionEndpoint() {
        return getConfig().get(ARTIFACT_RESOLUTION_ENDPOINT);
    }

    public void setArtifactResolutionEndpoint(String artifactResolutionEndpoint) {
        getConfig().put(ARTIFACT_RESOLUTION_ENDPOINT, artifactResolutionEndpoint);
    }

    public boolean isSignArtifactResolutionRequest() {
        return Boolean.valueOf(getConfig().get(SIGN_ARTIFACT_RESOLUTION_REQUEST));
    }

    public void setSignArtifactResolutionRequest(boolean signArtifactResolutionRequest) {
        getConfig().put(SIGN_ARTIFACT_RESOLUTION_REQUEST, String.valueOf(signArtifactResolutionRequest));
    }

    public Charset getCharSet() {
        return getConfig().get(CHAR_SET) != null ? Charset.forName(getConfig().get(CHAR_SET)) : StandardCharsets.UTF_8;
    }

    public void setCharSet(String charset) {
        getConfig().put(CHAR_SET, charset);
    }

    public Integer getMetadataValidUntilUnit() {
        return getConfig().get(METADATA_VALID_UNTIL_UNIT) != null ? Integer.parseInt(getConfig().get(METADATA_VALID_UNTIL_UNIT)) : null;
    }

    public void setMetadataValidUntilUnit(Integer unit) {
        getConfig().put(METADATA_VALID_UNTIL_UNIT, String.valueOf(unit));
    }

    public Integer getMetadataValidUntilPeriod() {
        return getConfig().get(METADATA_VALID_UNTIL_PERIOD) != null ? Integer.parseInt(getConfig().get(METADATA_VALID_UNTIL_PERIOD)) : null;
    }

    public void setMetadataValidUntilPeriod(Integer period) {
        getConfig().put(METADATA_VALID_UNTIL_UNIT, String.valueOf(period));
    }

    public boolean isMutualTLS() {
        return Boolean.parseBoolean(getConfig().get(ARTIFACT_RESOLUTION_MUTUAL_TLS));
    }

    public void setMutualTls(boolean mutualTls) {
        getConfig().put(ARTIFACT_RESOLUTION_MUTUAL_TLS, String.valueOf(mutualTls));
    }

    public void setIgnoreSamlAdviceNodes(boolean ignoreSamlAdviceNodes) {
        getConfig().put(IGNORE_SAML_ADVICE_NODES, String.valueOf(ignoreSamlAdviceNodes));
    }

    public boolean isIgnoreSamlAdviceNodes() {
        return Boolean.parseBoolean(getConfig().get(IGNORE_SAML_ADVICE_NODES));
    }

    public String getScoping() {
        return this.getConfig().get(AUTHN_REQUEST_SCOPING);
    }

    public void setScoping(String authnContextClassRefs) {
        this.getConfig().put(AUTHN_REQUEST_SCOPING, authnContextClassRefs);
    }

    public List<String> getLinkedProviders() {
        String linkedProviders = this.getConfig().get(LINKED_PROVIDERS);
        if (linkedProviders == null || linkedProviders.isEmpty())
            return new LinkedList<>();

        try {
            return List.of(linkedProviders);
        } catch (Exception e) {
            logger.warn("Could not json-deserialize linkedProviders config entry: " + linkedProviders, e);
            return new LinkedList<>();
        }
    }

    public void setLinkedProviders(String linkedProviders) {
        this.getConfig().put(LINKED_PROVIDERS, linkedProviders);
    }

    public List<String> getAttributeConsumingServiceValues() {
        return new ArrayList<>();
    }

}
