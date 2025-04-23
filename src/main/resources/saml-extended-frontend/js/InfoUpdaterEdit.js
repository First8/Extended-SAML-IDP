storedData = localStorage.getItem('pluginData');
document.addEventListener('DOMContentLoaded', function () {

    console.log(pluginData);

    if (storedData) {
        if (storedData) {

            var pluginData = JSON.parse(storedData);
            console.log(pluginData);


            function toggleCheckbox(configKey, checkbox) {

                if (pluginData.config && pluginData.config[configKey]) {
                    if (pluginData.config[configKey] == "true") {
                        checkbox.checked = true;
                    } else {
                        checkbox.checked = false;

                    }
                }

            }
            function toggleCheckbox1(configKey1, checkbox1) {

                if (pluginData && pluginData[configKey1]) {
                    if (pluginData[configKey1] == true || pluginData[configKey1] == "true") {
                        checkbox1.checked = true;
                    } else {
                        checkbox1.checked = false;

                    }
                }

            }


            toggleCheckbox('backchannelSupported', backchannel)
            toggleCheckbox('allowCreate', allowCreate)
            toggleCheckbox('postBindingResponse', httpPostBindingResponse)
            toggleCheckbox('postBindingAuthnRequest', httpPostBindingAuthnRequest)
            toggleCheckbox('postBindingLogout', httpPostBindingLogout)
            toggleCheckbox('wantAssertionsSigned', wantAssertionsSigned)
            toggleCheckbox('wantAssertionsEncrypted', wantAssertionsEncrypted)
            toggleCheckbox('forceAuthn', forceAuthentication)
            toggleCheckbox('signSpMetadata', signMetadata)
            toggleCheckbox('loginHint', passSubject)
            toggleCheckbox1('addReadTokenRoleOnCreate', storedTokensReadable)
            toggleCheckbox1('storeToken', storeToken)
            toggleCheckbox1('trustEmail', trustEmail)
            toggleCheckbox1('linkOnly', accountLinkingOnly)
            toggleCheckbox('hideOnLoginPage', hideLoginPage)
            toggleCheckbox('includeArtifactResolutionServiceMetadata', ArtifactResolutionService_in_metadata)
            toggleCheckbox('hideOnLoginPage', hideLoginPage)
            toggleCheckbox('signArtifactResolutionRequest', Sign_Artifact_Resolution_Request)
            toggleCheckbox('artifactResolutionHTTPArtifact', ArtifactResolution_via_HTTP_ARTIFACT)
            toggleCheckbox('artifactResolutionSOAP', Artifact_Resolution_with_SOAP)
            toggleCheckbox('artifactResolutionWithXmlHeader', Artifact_Resolution_with_XML_header)
            toggleCheckbox('mutualTls', Mutual_TLS)
            toggleCheckbox1('enabled', enabled)



            if (pluginData.config && pluginData.config.wantAuthnRequestsSigned) {

                console.log(`wantAuthnRequestsSigned_value: ${wantAuthnRequestsSigned.value}`);

                if (pluginData.config.wantAuthnRequestsSigned == "true") {
                    SignatureAlgorithm.removeAttribute("disabled");
                    SAMLSignatureKeyName.removeAttribute("disabled");
                    encryption_algorithm.removeAttribute("disabled")
                    wantAuthnRequestsSigned.checked = true;
                } else {
                    SignatureAlgorithm.setAttribute("disabled", "true");
                    SAMLSignatureKeyName.setAttribute("disabled", "true");
                    encryption_algorithm.setAttribute("disabled", "true");
                    wantAuthnRequestsSigned.checked = false;

                }
            }


            if (pluginData.config && pluginData.config.validateSignature) {
                validateSignatures_value = pluginData.config.validateSignature;
                console.log(`validateSignatures_value: ${validateSignatures_value}`);

                if (pluginData.config.validateSignature == "true") {
                    console.log(`validateSignatures_value: ${validateSignatures_value}`)
                    additionalField1.removeAttribute("disabled");
                    validateSignatures.checked = true;
                    if (pluginData.config.signingCertificate) {
                        updateField('ValidatingX509Certificates', pluginData.config.signingCertificate);
                    }
                } else {
                    validateSignatures.checked = false;
                    additionalField1.setAttribute("disabled", "true");

                }
            }




            if (pluginData.config && pluginData.config.artifactResolution) {
                Artifact_Resolution_value = pluginData.config.artifactResolution;
                console.log(`Artifact_Resolution_value: ${Artifact_Resolution_value}`);

                if (pluginData.config.artifactResolution == "true") {
                    console.log(`Artifact_Resolution_value: ${Artifact_Resolution_value}`)
                    Artifact_Resolution.checked = true;
                    console.log(`Artifact_Resolution_value: ${Artifact_Resolution_value}`)
                    additionalField_endpoint.removeAttribute("disabled");
                } else {
                    Artifact_Resolution.checked = false;
                    console.log(`Artifact_Resolution_value: ${Artifact_Resolution_value}`)
                    additionalField_endpoint.setAttribute("disabled", "true");
                    additionalField_endpoint.value = '';


                }
            }

        }


        function processAuthnContextArray(id, container) {
            var element = document.getElementById(id);
            if (pluginData.config && pluginData.config[id]) {
                var myArray = JSON.parse(pluginData.config[id]);
                updateField(id, myArray[0]);
                for (var i = 1; i < myArray.length; i++) {
                    const newItem = document.createElement("div");
                    newItem.className = "next-referral col-4";
                    newItem.innerHTML = '<input id="textinput_' + i + '" name="textinput" type="text" class="input_text" value="' + myArray[i] + '">';
                    container.appendChild(newItem);
                }
                console.log(pluginData.config[id]);
            }
        }



        processAuthnContextArray("authnContextClassRefs", ClassRefs_items);
        processAuthnContextArray("authnContextDeclRefs", DeclRefs_items);


        if (pluginData.backchannelSupported) {
            updateField('backchannel', pluginData.backchannelSupported);
        }

        if (pluginData.displayName) {
            updateField('displayName', pluginData.displayName);
        }
        if (pluginData.config.guiOrder) {
            updateField('displayOrder', pluginData.config.guiOrder);
        }
        if (pluginData.config.entityId) {
            updateField('spEntityId', pluginData.config.entityId)
        }
        if (pluginData.config.idpEntityId) {
            updateField('idpEntityId', pluginData.config.idpEntityId)
        }
        if (pluginData.config.singleSignOnServiceUrl) {
            updateField('ssoServiceUrl', pluginData.config.singleSignOnServiceUrl);
        }
        if (pluginData.config.singleLogoutServiceUrl) {
            updateField('sloServiceUrl', pluginData.config.singleLogoutServiceUrl);
        }

        if (pluginData.config.nameIDPolicyFormat) {
            const valueAfterFormat = extractValueAfterFormat(pluginData.config.nameIDPolicyFormat);
            updateField('nameIdPolicy', valueAfterFormat);
            console.log(valueAfterFormat);
        }
        if (pluginData.config.principalType) {
            updateField('principalType', pluginData.config.principalType);
            if (pluginData.config.principalType == "ATTRIBUTE" || pluginData.config.principalType == "FRIENDLY_ATTRIBUTE") {
                if (pluginData.config.principalAttribute) {
                    updateField('principalAttribute', pluginData.config.principalAttribute);

                }
                principalAttribute_input.removeAttribute("disabled");
            } else {
                principalAttribute_input.setAttribute("disabled", "true");
                principalAttribute_input.value = '';

            }
        };


        if (pluginData.config.encryptionAlgorithm) {
            updateField('encryption_algorithm', pluginData.config.encryptionAlgorithm);
        }

        if (pluginData.config.signatureAlgorithm) {
            updateField('SignatureAlgorithm', pluginData.config.signatureAlgorithm);
        }
        if (pluginData.config.xmlSigKeyInfoKeyNameTransformer) {
            updateField('SAMLSignatureKeyName', pluginData.config.xmlSigKeyInfoKeyNameTransformer);
        }

        if (pluginData.config.metadataValidUntilUnit) {
            updateField('Metadata_expires_in', pluginData.config.metadataValidUntilUnit);
        }
        if (pluginData.config.metadataValidUntilPeriod) {
            updateField('metadataValidUntilPeriod', pluginData.config.metadataValidUntilPeriod);
        }
        if (pluginData.config.linkedProviders) {
            updateField('Linked_Providers', pluginData.config.linkedProviders);
        }
        if (pluginData.config.artifactResolutionEndpoint) {
            updateField('Artifact_Resolution_Endpoint', pluginData.config.artifactResolutionEndpoint);
        }
        if (pluginData.config.charSet) {
            updateField('CharacterSet', pluginData.config.charSet);
        }

        if (pluginData.alias) {
            updateField('alias', pluginData.alias);

        }
        var selectedrealm = localStorage.getItem('selectedRealm');
        var ServerUrl1 = localStorage.getItem('ServerUrl')
        var pluginalias=localStorage.setItem('pluginalias',`${pluginData.alias}`)
        document.getElementById('redirectUri').value = `${ServerUrl1}/realms/${selectedrealm}/broker/${pluginData.alias}/endpoint`

        if (pluginData.config.allowedClockSkew) {
            updateField('allowedClockSkew', pluginData.config.allowedClockSkew);
        }

        if (pluginData.config.attributeConsumingServiceIndex) {
            updateField('attributeConsumingServiceIndex', pluginData.config.attributeConsumingServiceIndex);
        }

        if (pluginData.config.attributeConsumingServiceName) {
            updateField('attributeConsumingServiceName', pluginData.config.attributeConsumingServiceName);
        }

        if (pluginData.config.attributeConsumingServiceName) {
            updateField('attributeConsumingServiceName', pluginData.config.attributeConsumingServiceName);
        }
        if (pluginData.config.authnContextComparisonType) {
            updateField('comparison', pluginData.config.authnContextComparisonType);
        }

        if (pluginData.config.syncMode) {
            updateField('syncMode', pluginData.config.syncMode);
        }


    }
}

);

function toggleCheckbox(configKey, checkbox) {

    if (pluginData.config && pluginData.config[configKey]) {
        if (pluginData.config[configKey] == "true") {
            checkbox.checked = true;
        } else {
            checkbox.checked = false;

        }
    }

}

function extractValueAfterFormat(text) {
    const regex = /nameid-format:(\w+)/;
    const match = text.match(regex);
    return match ? match[1] : null;
}



function updateField(fieldName, value) {
    document.getElementById(fieldName).value = value;
}
