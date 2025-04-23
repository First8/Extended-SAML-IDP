#!/bin/bash
function copy_file() {
  KC_DEST=$(echo ${1} | sed 's/^\(.*\/\)\(src\/.*\/\)\(.*\.java\)/\2/')
  KC_DEST=${KC_DEST/org/nl\/first8}

  cp ${KEYCLOAK}/${1} ${KC_DEST}
}

while [[ $# -gt 1 ]]; do
	key="$1"

	case $key in
		-k|--keycloak)
		KEYCLOAK="$2"
		shift # past argument
		;;
		-d|--destination)
		DESTINATION="$2"
		shift # past argument
		;;
		*)
			# unknown option
		;;
	esac
	shift # past argument or value
done

if [ -z "$KEYCLOAK" ]; then
  echo "No keycloak source directory found. Use -k | --keycloak <dir> to "
else
  copy_file "services/src/main/java/org/keycloak/broker/saml/mappers/AdvancedAttributeToRoleMapper.java"
  copy_file "services/src/main/java/org/keycloak/broker/saml/mappers/AttributeToRoleMapper.java"
  copy_file "services/src/main/java/org/keycloak/broker/saml/mappers/UserAttributeMapper.java"
  copy_file "services/src/main/java/org/keycloak/broker/saml/mappers/UsernameTemplateMapper.java"

  copy_file "services/src/main/java/org/keycloak/broker/saml/SAMLDataMarshaller.java"
  copy_file "services/src/main/java/org/keycloak/broker/saml/SAMLEndpoint.java"
  copy_file "services/src/main/java/org/keycloak/broker/saml/SAMLIdentityProvider.java"
  copy_file "services/src/main/java/org/keycloak/broker/saml/SAMLIdentityProviderConfig.java"
  copy_file "services/src/main/java/org/keycloak/broker/saml/SAMLIdentityProviderFactory.java"

  copy_file "saml-core-api/src/main/java/org/keycloak/dom/saml/v2/assertion/AssertionType.java"
  copy_file "saml-core-api/src/main/java/org/keycloak/dom/saml/v2/assertion/AttributeStatementType.java"

  copy_file "saml-core-api/src/main/java/org/keycloak/dom/saml/v2/metadata/AttributeConsumingServiceType.java"
  copy_file "saml-core-api/src/main/java/org/keycloak/dom/saml/v2/metadata/EntitiesDescriptorType.java"
  copy_file "saml-core-api/src/main/java/org/keycloak/dom/saml/v2/metadata/EntityDescriptorType.java"
  copy_file "saml-core-api/src/main/java/org/keycloak/dom/saml/v2/metadata/SPSSODescriptorType.java"

  copy_file "saml-core-api/src/main/java/org/keycloak/dom/saml/v2/protocol/ResponseType.java"

  copy_file "services/src/main/java/org/keycloak/protocol/saml/mappers/SamlMetadataDescriptorUpdater.java"

  copy_file "services/src/main/java/org/keycloak/protocol/saml/JaxrsSAML2BindingBuilder.java"
  copy_file "services/src/main/java/org/keycloak/protocol/saml/mappers/SamlMetadataDescriptorUpdater.java"
  copy_file "services/src/main/java/org/keycloak/protocol/saml/SamlProtocolUtils.java"

  copy_file "saml-core-api/src/main/java/org/keycloak/saml/common/constants/JBossSAMLConstants.java"

  copy_file "saml-core/src/main/java/org/keycloak/saml/processing/api/saml/v2/request/SAML2Request.java"
  copy_file "saml-core/src/main/java/org/keycloak/saml/processing/api/saml/v2/request/SecurityActions.java"

  copy_file "saml-core/src/main/java/org/keycloak/saml/processing/api/saml/v2/response/SAML2Response.java"

  copy_file "saml-core/src/main/java/org/keycloak/saml/processing/api/saml/v2/sig/SAML2Signature.java"

  copy_file "saml-core/src/main/java/org/keycloak/saml/processing/core/parsers/saml/assertion/AbstractStaxSamlAssertionParser.java"
  copy_file "saml-core/src/main/java/org/keycloak/saml/processing/core/parsers/saml/assertion/SAMLAssertionParser.java"
  copy_file "saml-core/src/main/java/org/keycloak/saml/processing/core/parsers/saml/assertion/SAMLAssertionQNames.java"
  copy_file "saml-core/src/main/java/org/keycloak/saml/processing/core/parsers/saml/assertion/SAMLAttributeStatementParser.java"

  copy_file "saml-core/src/main/java/org/keycloak/saml/processing/core/parsers/saml/metadata/SAMLAttributeConsumingServiceParser.java"
  copy_file "saml-core/src/main/java/org/keycloak/saml/processing/core/parsers/saml/metadata/SAMLEntitiesDescriptorParser.java"
  copy_file "saml-core/src/main/java/org/keycloak/saml/processing/core/parsers/saml/metadata/SAMLEntityDescriptorParser.java"
  copy_file "saml-core/src/main/java/org/keycloak/saml/processing/core/parsers/saml/metadata/SAMLSPSSODescriptorParser.java"

  copy_file "saml-core/src/main/java/org/keycloak/saml/processing/core/parsers/saml/protocol/SAMLArtifactResponseParser.java"
  copy_file "saml-core/src/main/java/org/keycloak/saml/processing/core/parsers/saml/protocol/SAMLResponseParser.java"

  copy_file "saml-core/src/main/java/org/keycloak/saml/processing/core/parsers/saml/SAMLParser.java"

  copy_file "saml-core/src/main/java/org/keycloak/saml/processing/core/saml/v2/util/AssertionUtil.java"

  copy_file "saml-core/src/main/java/org/keycloak/saml/processing/core/saml/v2/writers/SAMLAssertionWriter.java"
  copy_file "saml-core/src/main/java/org/keycloak/saml/processing/core/saml/v2/writers/SAMLMetadataWriter.java"
  copy_file "saml-core/src/main/java/org/keycloak/saml/processing/core/saml/v2/writers/SAMLRequestWriter.java"
  copy_file "saml-core/src/main/java/org/keycloak/saml/processing/core/saml/v2/writers/SAMLResponseWriter.java"

  copy_file "saml-core/src/main/java/org/keycloak/saml/processing/core/util/XMLSignatureUtil.java"

  copy_file "saml-core/src/main/java/org/keycloak/saml/SAML2AuthnRequestBuilder.java"
  copy_file "saml-core/src/main/java/org/keycloak/saml/SAMLRequestParser.java"

  cp ${KEYCLOAK}"/themes/src/main/resources/theme/base/admin/resources/partials/realm-identity-provider-saml.html" "src/main/resources/theme-resources/resources/partials/"
fi