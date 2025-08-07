#!/bin/bash

if [ $# -ne 2 ]; then
    echo "Usage: $0 OLD_BRANCH NEW_BRANCH"
    exit 1
fi

OLD_BRANCH="$1"
NEW_BRANCH="$2"

echo "Comparing Java files between branches:"
echo "  OLD_BRANCH: $OLD_BRANCH"
echo "  NEW_BRANCH: $NEW_BRANCH"

OLD_DIR="./diff/old"
NEW_DIR="./diff/new"
PATCH_FILE="./diffgen.patch"

FILES=(
  services/src/main/java/org/keycloak/authentication/authenticators/broker/util/SerializedBrokeredIdentityContext.java
  services/src/main/java/org/keycloak/broker/saml/mappers/AdvancedAttributeToRoleMapper.java
  services/src/main/java/org/keycloak/broker/saml/mappers/AttributeToRoleMapper.java
  services/src/main/java/org/keycloak/broker/saml/mappers/UserAttributeMapper.java
  services/src/main/java/org/keycloak/broker/saml/mappers/UsernameTemplateMapper.java
  services/src/main/java/org/keycloak/broker/saml/SAMLDataMarshaller.java
  services/src/main/java/org/keycloak/broker/saml/SAMLEndpoint.java
  services/src/main/java/org/keycloak/broker/saml/SAMLIdentityProvider.java
  services/src/main/java/org/keycloak/broker/saml/SAMLIdentityProviderConfig.java
  services/src/main/java/org/keycloak/broker/saml/SAMLIdentityProviderFactory.java
  saml-core-api/src/main/java/org/keycloak/dom/saml/v2/assertion/AssertionType.java
  saml-core-api/src/main/java/org/keycloak/dom/saml/v2/assertion/AttributeStatementType.java
  saml-core-api/src/main/java/org/keycloak/dom/saml/v2/metadata/AttributeConsumingServiceType.java
  saml-core-api/src/main/java/org/keycloak/dom/saml/v2/metadata/EntitiesDescriptorType.java
  saml-core-api/src/main/java/org/keycloak/dom/saml/v2/metadata/EntityDescriptorType.java
  saml-core-api/src/main/java/org/keycloak/dom/saml/v2/metadata/SPSSODescriptorType.java
  saml-core-api/src/main/java/org/keycloak/dom/saml/v2/protocol/ResponseType.java
  services/src/main/java/org/keycloak/protocol/saml/mappers/SamlMetadataDescriptorUpdater.java
  services/src/main/java/org/keycloak/protocol/saml/JaxrsSAML2BindingBuilder.java
  services/src/main/java/org/keycloak/protocol/saml/SamlProtocolUtils.java
  saml-core-api/src/main/java/org/keycloak/saml/common/constants/JBossSAMLConstants.java
  saml-core/src/main/java/org/keycloak/saml/processing/api/saml/v2/request/SAML2Request.java
  saml-core/src/main/java/org/keycloak/saml/processing/api/saml/v2/request/SecurityActions.java
  saml-core/src/main/java/org/keycloak/saml/processing/api/saml/v2/response/SAML2Response.java
  saml-core/src/main/java/org/keycloak/saml/processing/api/saml/v2/sig/SAML2Signature.java
  saml-core/src/main/java/org/keycloak/saml/processing/core/parsers/saml/assertion/AbstractStaxSamlAssertionParser.java
  saml-core/src/main/java/org/keycloak/saml/processing/core/parsers/saml/assertion/SAMLAssertionParser.java
  saml-core/src/main/java/org/keycloak/saml/processing/core/parsers/saml/assertion/SAMLAssertionQNames.java
  saml-core/src/main/java/org/keycloak/saml/processing/core/parsers/saml/assertion/SAMLAttributeParser.java
  saml-core/src/main/java/org/keycloak/saml/processing/core/parsers/saml/assertion/SAMLAttributeStatementParser.java
  saml-core/src/main/java/org/keycloak/saml/processing/core/parsers/saml/assertion/SAMLAttributeValueParser.java
  saml-core/src/main/java/org/keycloak/saml/processing/core/parsers/saml/metadata/SAMLAttributeConsumingServiceParser.java
  saml-core/src/main/java/org/keycloak/saml/processing/core/parsers/saml/metadata/SAMLEntitiesDescriptorParser.java
  saml-core/src/main/java/org/keycloak/saml/processing/core/parsers/saml/metadata/SAMLEntityDescriptorParser.java
  saml-core/src/main/java/org/keycloak/saml/processing/core/parsers/saml/metadata/SAMLSPSSODescriptorParser.java
  saml-core/src/main/java/org/keycloak/saml/processing/core/parsers/saml/protocol/SAMLArtifactResponseParser.java
  saml-core/src/main/java/org/keycloak/saml/processing/core/parsers/saml/protocol/SAMLResponseParser.java
  saml-core/src/main/java/org/keycloak/saml/processing/core/parsers/saml/SAMLParser.java
  saml-core/src/main/java/org/keycloak/saml/processing/core/saml/v2/factories/JBossSAMLAuthnResponseFactory.java
  saml-core/src/main/java/org/keycloak/saml/processing/core/saml/v2/factories/SAMLAssertionFactory.java
  saml-core/src/main/java/org/keycloak/saml/processing/core/saml/v2/util/AssertionUtil.java
  saml-core/src/main/java/org/keycloak/saml/processing/core/saml/v2/util/SAMLMetadataUtil.java
  saml-core/src/main/java/org/keycloak/saml/processing/core/saml/v2/writers/BaseWriter.java
  saml-core/src/main/java/org/keycloak/saml/processing/core/saml/v2/writers/SAMLAssertionWriter.java
  saml-core/src/main/java/org/keycloak/saml/processing/core/saml/v2/writers/SAMLMetadataWriter.java
  saml-core/src/main/java/org/keycloak/saml/processing/core/saml/v2/writers/SAMLRequestWriter.java
  saml-core/src/main/java/org/keycloak/saml/processing/core/saml/v2/writers/SAMLResponseWriter.java
  saml-core/src/main/java/org/keycloak/saml/processing/core/util/XMLSignatureUtil.java
  saml-core/src/main/java/org/keycloak/saml/SAML2AuthnRequestBuilder.java
  saml-core/src/main/java/org/keycloak/saml/SAMLRequestParser.java
  services/src/main/java/org/keycloak/services/resources/IdentityBrokerService.java
)

# Clean up any previous run
rm -rf "$OLD_DIR" "$NEW_DIR" "$PATCH_FILE"
mkdir -p "$OLD_DIR" "$NEW_DIR"

echo "Exporting files..."

for FILE in "${FILES[@]}"; do
  mkdir -p "$OLD_DIR/$(dirname "$FILE")"
  git show "$OLD_BRANCH:$FILE" > "$OLD_DIR/$FILE" 2>/dev/null || echo "Missing in $OLD_BRANCH: $FILE"

  mkdir -p "$NEW_DIR/$(dirname "$FILE")"
  git show "$NEW_BRANCH:$FILE" > "$NEW_DIR/$FILE" 2>/dev/null || echo "Missing in $NEW_BRANCH: $FILE"
done

echo "File count (.java only):"
echo "  $OLD_BRANCH: $(find "$OLD_DIR" -type f -name '*.java' | wc -l)"
echo "  $NEW_BRANCH: $(find "$NEW_DIR" -type f -name '*.java' | wc -l)"

echo "Creating patch..."
diff --color=never -ruN "$OLD_DIR" "$NEW_DIR" > "$PATCH_FILE"

# Post-process diff for portability or project-specific needs
safe_sed() {
  sed "$1" "$2" > "$2.tmp" && mv "$2.tmp" "$2"
}

safe_sed "s|$OLD_DIR/saml-core/||g" "$PATCH_FILE"
safe_sed "s|$NEW_DIR/saml-core/||g" "$PATCH_FILE"
safe_sed "s|$OLD_DIR/services/||g" "$PATCH_FILE"
safe_sed "s|$NEW_DIR/services/||g" "$PATCH_FILE"
safe_sed 's|org/keycloak/|nl/first8/keycloak/|g' "$PATCH_FILE"

echo "Patch created at: $PATCH_FILE"
