package nl.first8.keycloak.protocol.saml;

import nl.first8.keycloak.dom.saml.v2.metadata.EntityDescriptorType;
import org.keycloak.models.IdentityProviderMapperModel;

public interface SamlMetadataDescriptorUpdater {
    void updateMetadata(IdentityProviderMapperModel identityProviderMapperModel, EntityDescriptorType entityDescriptorType);
}