package nl.first8.keycloak.protocol.saml.mappers;

import nl.first8.keycloak.dom.saml.v2.metadata.EntityDescriptorType;
import org.keycloak.models.IdentityProviderMapperModel;

public interface SamlMetadataDescriptorUpdater {
    void updateMetadata(IdentityProviderMapperModel mapperModel, EntityDescriptorType descriptor);
}
