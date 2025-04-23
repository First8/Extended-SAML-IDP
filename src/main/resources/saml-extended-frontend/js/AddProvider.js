let importClicked = false;
import_data.addEventListener('click', async (event) => {
    event.preventDefault();
    let alias = alias_input.value;
    keycloak.updateToken(300).then(async (bool) => {

        if (bool) {
            let isValid = true;
            hasFocused = false;
            if (!alias_input.value) {
                handleInvalidInput(alias_input, errorMessage, "Required field !");
                isValid = false;
            } else {
                handleValidInput(alias_input, errorMessage,"");
            }
            if (!samlEntityDescriptor_input.value ||!samlEntityDescriptor_input.value.startsWith("https://")) {
                handleInvalidInput(samlEntityDescriptor_input, samlEntityDescriptor_errorMessage_URL, "Enter a valid URL!");
                isValid = false;
            }
            else
            { handleValidInput(samlEntityDescriptor_input, samlEntityDescriptor_errorMessage_URL,"");
            }
            handleValidInput(Single_Sign_On_Service_URL_input, errorMessage_URL,"");



            if (!isValid)
            {return}
            var newAccessToken = keycloak.token;

            const checkPluginResponse = await fetch(`${ServerUrl}/admin/realms/${selectedrealm}/identity-provider/instances/${alias}`, {
                method: 'GET',
                headers: {
                    'Authorization': `Bearer ${newAccessToken}`
                }
            });

            if (checkPluginResponse.ok) {
                alias_input.classList.remove('input_text');
                alias_input.classList.add('red-border');
                alias_input.focus();
                errorMessage.textContent = ("Choose a unique *alias* that does not exist");
                alert(`Could not create the identity provider: Identity Provider "${alias}" already exists.`);
                // Add your logic for updating the existing plugin if needed
            } else if (checkPluginResponse.status === 404) {
                // Plugin not found, add it using a POST request
                const updatePluginResponse = await fetch(`${ServerUrl}/admin/realms/${selectedrealm}/identity-provider/import-config`, {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${newAccessToken}`,
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify({
                        providerId: "saml-extended",
                        fromUrl: `${samlEntityDescriptor.value}`
                    })
                });

                if (updatePluginResponse.ok) {
                    const config = await updatePluginResponse.json();
                    samlEntityDescriptor_input.classList.remove('red-border');
                    samlEntityDescriptor_input.classList.add('input_text');
                    samlEntityDescriptor_errorMessage_URL.textContent = "";
                    importClicked = true;
                    document.getElementById("submit").disabled = false
                    var data =
                        {"alias": alias, "enabled": "true",
                        "providerId": "saml-extended", "config": {
                                "allowCreate": "true",
                                ...config
                    }

                        };
                    var script = document.createElement('script');
                    localStorage.setItem('pluginData', JSON.stringify(data));
                    script.src = '../../samlconfig/js/InfoUpdaterAdd';
                    script.type = 'text/javascript';
                    document.head.appendChild(script);
                }
                else{alert("Failed to import data")}
            }}
    });
});
function updateField(fieldName, value) {
    document.getElementById(fieldName).value = value;
}
add.addEventListener('click', () => {
    event.preventDefault();
    handleAttributeServices();
    var useEntityDescriptor=document.getElementById("useEntityDescriptor")
    if (useEntityDescriptor.checked) {
        let isValid = true;
        hasFocused = false;
        if (!alias_input.value) {
            handleInvalidInput(alias_input, errorMessage, "Required field !");
            isValid = false;
        } else {
            handleValidInput(alias_input, errorMessage,"");
        }
        if (!samlEntityDescriptor_input.value ||!samlEntityDescriptor_input.value.startsWith("https://")) {
            handleInvalidInput(samlEntityDescriptor_input, samlEntityDescriptor_errorMessage_URL, "Enter a valid URL!");}
        else
        { handleValidInput(samlEntityDescriptor_input, samlEntityDescriptor_errorMessage_URL,"");
        }

            if (!Single_Sign_On_Service_URL_input.value || !Single_Sign_On_Service_URL_input.value.startsWith("https://")) {
                handleInvalidInput(Single_Sign_On_Service_URL_input, errorMessage_URL, "Enter a valid URL");
                isValid = false;
            } else {
                handleValidInput(Single_Sign_On_Service_URL_input, errorMessage_URL,"");
            }

            if (Single_Logout_Service_URL_input.value && !Single_Logout_Service_URL_input.value.startsWith("https://")) {
                handleInvalidInput(Single_Logout_Service_URL_input, errorMessage_URL_logout, "Enter a valid URL");
                isValid = false;
            } else {
                handleValidInput(Single_Logout_Service_URL_input, errorMessage_URL_logout,"");
            }

        if (!isValid) {
            return;
        }
        if (!importClicked){
            handleInvalidInput(samlEntityDescriptor_input, samlEntityDescriptor_errorMessage_URL, "Make sure to press the import button first");
            return;
        }

        const data = JSON.parse(localStorage.getItem('pluginData'));

        keycloak.updateToken(300).then(async (bool) => {
            if (bool) {
                var newAccessToken = keycloak.token;
                var selectedrealm = localStorage.getItem('selectedRealm');

                const updatePluginResponse = await fetch(`${ServerUrl}/admin/realms/${selectedrealm}/identity-provider/instances`, {
                    method: 'POST',
                    headers: {
                        'Authorization': `Bearer ${newAccessToken}`,
                        'Content-Type': 'application/json',
                    },
                    body: JSON.stringify(data),
                });

                if (updatePluginResponse.ok) {
                    alert("Plugin added successfully.");
                    window.location.href = `${editprovider}`;
                    localStorage.setItem('pluginData', JSON.stringify(data));
                    localStorage.setItem('pluginalias', data.alias);
                    getAllPlugins(newAccessToken, selectedrealm);
                } else {
                    console.error('Failed to add plugin:', updatePluginResponse.status, updatePluginResponse.statusText);
                    alert("Failed to add plugin");
                }
            }
        });
    } else {
        var authnContextClassRefs = [];
        const ClassRefs_inputs = ClassRefs_items.querySelectorAll("input");
        ClassRefs_inputs.forEach(input => {
            if (input.value.trim() !== "") {
                authnContextClassRefs.push(input.value);
            }
        });
        const authnContextDeclRefs = [];
        const DeclRefs_inputs = DeclRefs_items.querySelectorAll("input");
        DeclRefs_inputs.forEach(input => {
            if (input.value.trim() !== "") {
                authnContextDeclRefs.push(input.value);
            }
        });
        function getValueFromElement(selector) {
            var element = document.querySelector(selector);
            return element ? element.value.trim() : null;
        }

        var serviceName = getValueFromElement('.serviceName');
        var attributeValue = getValueFromElement('.attributeValue');
        var friendlyName = getValueFromElement('.friendlyName');
        var attributeName = getValueFromElement('.attributeName');

        var Single_Sign_On_Service_URL = Single_Sign_On_Service_URL_input.value;
        var Single_Logout_Service_URL = Single_Logout_Service_URL_input.value;
        var nameIdPolicy = nameIdPolicy_input.value;
        var nameIdPolicy1 = `urn:oasis:names:tc:SAML:2.0:nameid-format:${nameIdPolicy}`;
        var alias = alias_input.value;
        var data = {
            "alias": alias,
            "displayName": Display_Name_input.value,
            "providerId": "saml-extended",
            "enabled": "true",
            "updateProfileFirstLoginMode": "on",
            "trustEmail": trustEmail.value,
            "storeToken": storeToken.value,
            "addReadTokenRoleOnCreate": storedTokensReadable.value,
            "authenticateByDefault": "false",
            "linkOnly": accountLinkingOnly.value,
            "firstBrokerLoginFlowAlias": firstLoginFlow_input.value,
            "postBrokerLoginFlowAlias": postLoginFlow_input.value,
            config: {
                "postBindingLogout": httpPostBindingLogout.value,
                "authnContextClassRefs": authnContextClassRefs.length > 0 ? JSON.stringify(authnContextClassRefs) : undefined,
                "postBindingResponse": httpPostBindingResponse.value,
                "singleLogoutServiceUrl": Single_Logout_Service_URL,
                "authnContextDeclRefs": authnContextDeclRefs.length > 0 ? JSON.stringify(authnContextDeclRefs) : undefined,
                "backchannelSupported": backchannel.value,
                "xmlSigKeyInfoKeyNameTransformer": SAMLSignatureKeyName_input.value,
                "idpEntityId": Identity_Provider_Entity_ID_input.value,
                "loginHint": passSubject.value,
                "encryptionAlgorithm": encryption_algorithm.value,
                "allowCreate": allowCreate.value,
                "authnContextComparisonType": comparison_input.value,
                "syncMode": syncMode_input.value,
                "singleSignOnServiceUrl": Single_Sign_On_Service_URL,
                "wantAuthnRequestsSigned": wantAuthnRequestsSigned.value,
                "allowedClockSkew": allowedClockSkew_input.value,
                "guiOrder": Display_Order_input.value,
                "validateSignature": validateSignatures.value,
                "hideOnLoginPage": hideLoginPage.value,
                "signingCertificate": ValidatingX509Certificates_input.value,
                "nameIDPolicyFormat": nameIdPolicy1,
                "entityId": Service_Provider_Entity_ID_input.value,
                "attributeConsumingServiceName": attributeConsumingServiceName_input.value,
                "signSpMetadata": signMetadata.value,
                "wantAssertionsEncrypted": wantAssertionsEncrypted.value,
                "signatureAlgorithm": SignatureAlgorithm_input.value,
                "wantAssertionsSigned": wantAssertionsSigned.value,
                "postBindingAuthnRequest":httpPostBindingAuthnRequest.value,
                "forceAuthn": forceAuthentication.value,
                "attributeConsumingServiceIndex": attributeConsumingServiceIndex_input.value,
                "principalType": principalType_input.value,
                "principalAttribute": principalAttribute_input.value,
                "includeArtifactResolutionServiceMetadata": ArtifactResolutionService_in_metadata.value,
                "artifactResolution": Artifact_Resolution.value,
                "artifactResolutionEndpoint": Artifact_Resolution_Endpoint_input.value,
                "signArtifactResolutionRequest": Sign_Artifact_Resolution_Request.value,
                "artifactResolutionSOAP": Artifact_Resolution_with_SOAP.value,
                "artifactResolutionWithXmlHeader": Artifact_Resolution_with_XML_header.value,
                "artifactResolutionHTTPArtifact": ArtifactResolution_via_HTTP_ARTIFACT.value,
                "mutualTls": Mutual_TLS.value,
                "charSet": CharacterSet_input.value,
                "metadataValidUntilUnit": Metadata_expires_in_input.value,
                "metadataValidUntilPeriod": metadataValidUntilPeriod_input.value,
                "linkedProviders": Linked_Providers_input.value,
                "sendIdTokenOnLogout": id_token_hint.value,
                "sendClientIdOnLogout": client_id_in_logout_requests.value,
                "enabledFromMetadata": useEntityDescriptor.value,
                "metadataDescriptorUrl": samlEntityDescriptor_input.value,
                "attributeConsumingServiceMetadata":attributeServicesArray.length > 0 ? JSON.stringify(attributeServicesArray) : undefined

            }}

            let isValid = true;
            hasFocused = false;
            if (!alias_input.value) {
                handleInvalidInput(alias_input, errorMessage, "Required field !");
                isValid = false;
            } else {
                handleValidInput(alias_input, errorMessage,"");
            }

            if (!Single_Sign_On_Service_URL_input.value || !Single_Sign_On_Service_URL_input.value.startsWith("https://")) {
                handleInvalidInput(Single_Sign_On_Service_URL_input, errorMessage_URL, "Enter a valid URL");
                isValid = false;
            } else {
                handleValidInput(Single_Sign_On_Service_URL_input, errorMessage_URL,"");
            }

            if (Single_Logout_Service_URL_input.value && !Single_Logout_Service_URL_input.value.startsWith("https://")) {
                handleInvalidInput(Single_Logout_Service_URL_input, errorMessage_URL_logout, "Enter a valid URL");
                isValid = false;
            } else {
                handleValidInput(Single_Logout_Service_URL_input, errorMessage_URL_logout,"");
            }

            if (!isValid) {
                return;
            }

    removeEmptyStrings(data);

    const configKeys = Object.keys(data.config);
    for (const key of configKeys) {
        if (typeof data.config[key] === 'string' && data.config[key].trim() === "") {
            delete data.config[key];
        }
    }
    if (Array.isArray(data.config.authnContextClassRefs) && data.config.authnContextClassRefs.length === 0) {
        delete data.config.authnContextClassRefs;
    }

    if (Array.isArray(data.config.authnContextDeclRefs) && data.config.authnContextDeclRefs.length === 0) {
        delete data.config.authnContextDeclRefs;
    }

    // Update token and execute the following code when the token is successfully updated 
    keycloak.updateToken(300).then((bool) => {
        if (bool) {

            // Code to be executed after token update 
            var newAccessToken = keycloak.token;
           var selectedrealm= localStorage.getItem('selectedRealm');
            // Sending a GET request to check if the plugin exists
            fetch(`${ServerUrl}/admin/realms/${selectedrealm}/identity-provider/instances/${alias}`, {
                method: 'GET',
                headers: {
                    'Authorization': ` Bearer ${newAccessToken}`, // Fix here
                },
            })
                .then(async checkPluginResponse => {
                    if (checkPluginResponse.ok) {
                        handleInvalidInput(alias_input, errorMessage, "Choose a unique *alias* that does not exist");
                        alert(`Could not create the identity provider: Identity Provider "${alias}" already exists.`);
                        // Add your logic for updating the existing plugin if needed 
                    } else if (checkPluginResponse.status === 404) {
                        // Plugin not found, add it using a POST request 
                        const updatePluginResponse = await fetch(`${ServerUrl}/admin/realms/${selectedrealm}/identity-provider/instances`, {
                            method: 'POST',
                            headers: {
                                'Authorization': ` Bearer ${newAccessToken}`, // Fix here
                                'Content-Type': 'application/json',
                            },
                            body: JSON.stringify(data),
                        }

                        );

                        // Handle the response of the POST request 
                        if (updatePluginResponse.ok) {
                            alert("Plugin added successfully.");
                            window.location.href =`${editprovider}`;
                            localStorage.setItem('pluginData', JSON.stringify(data));
                            localStorage.setItem('pluginalias', pluginData.alias);
                            getAllPlugins(newAccessToken,selectedrealm);
                        } else {
                            console.error('Failed to add plugin:', updatePluginResponse.status, updatePluginResponse.statusText);
                            alert("Failed to add plugin");
                        }
                    } else {
                        // If there is another status, an error occurred 
                        console.error(`Failed to retrieve the plugin. Response: ${checkPluginResponse.statusText}`);
                        alert("Failed to retrieve the plugin");
                        throw new Error(`Failed to retrieve the plugin. Response: ${checkPluginResponse.statusText}`);
                    }
                })
                .catch(error => {
                    console.error('Error during the process:', error);
                });
        }

    });
}});
