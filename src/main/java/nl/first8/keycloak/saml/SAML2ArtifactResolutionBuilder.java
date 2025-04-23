package nl.first8.keycloak.saml;

import org.jboss.logging.Logger;
import org.keycloak.dom.saml.v2.assertion.NameIDType;
import org.keycloak.dom.saml.v2.protocol.ArtifactResolveType;
import org.keycloak.saml.common.constants.GeneralConstants;
import org.keycloak.saml.common.exceptions.ConfigurationException;
import org.keycloak.saml.common.exceptions.ParsingException;
import org.keycloak.saml.common.exceptions.ProcessingException;
import org.keycloak.saml.common.util.DocumentUtil;
import org.keycloak.saml.common.util.StaxUtil;
import org.keycloak.saml.processing.core.saml.v2.common.IDGenerator;
import org.keycloak.saml.processing.core.saml.v2.util.XMLTimeUtil;
import org.keycloak.saml.processing.core.saml.v2.writers.SAMLRequestWriter;
import org.w3c.dom.Document;

import java.io.ByteArrayOutputStream;

public class SAML2ArtifactResolutionBuilder {

    protected static final Logger logger = Logger.getLogger(SAML2ArtifactResolutionBuilder.class);

    private final ArtifactResolveType artifactResolveType;
    protected String artifact;
    protected String issuer;

    public SAML2ArtifactResolutionBuilder() {
        this.artifactResolveType = new ArtifactResolveType(IDGenerator.create("ID_"), XMLTimeUtil.getIssueInstant());
    }

    public SAML2ArtifactResolutionBuilder artifact(String artifact) {
        this.artifact = artifact;
        return this;
    }

    public SAML2ArtifactResolutionBuilder issuer(String issuer) {
        this.issuer = issuer;
        return this;
    }

    public Document toDocument() {
        try {
            ArtifactResolveType art = this.artifactResolveType;
            art.setArtifact(artifact);
            NameIDType nameIDType = new NameIDType();
            nameIDType.setValue(this.issuer);

            art.setIssuer(nameIDType);

            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            SAMLRequestWriter writer = new SAMLRequestWriter(StaxUtil.getXMLStreamWriter(bos));
            writer.write(artifactResolveType);

            String output = new String(bos.toByteArray(), GeneralConstants.SAML_CHARSET);
            logger.tracef("SAMLResolve query to send to endpoint: %s", output);
            return DocumentUtil.getDocument(output);
        } catch (ParsingException | ConfigurationException | ProcessingException e) {
            logger.errorf("Could not convert %s to a document. Throwing RuntimeException.", artifactResolveType);
            throw new RuntimeException("Could not convert " + artifactResolveType + " to a document.", e);
        }
    }
}
