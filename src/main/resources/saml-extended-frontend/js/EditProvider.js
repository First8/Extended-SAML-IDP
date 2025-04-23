edit.addEventListener('click', () => {

    keycloak.updateToken(300).then((bool) => {
        if (bool) {
            newAccessToken = keycloak.token;

            var authnContextClassRefs = []
            const ClassRefs_inputs = ClassRefs_items.querySelectorAll("input");
            ClassRefs_inputs.forEach(input => {
                if (input.value.trim() !== "") {
                    authnContextClassRefs.push(input.value);
                }
            });
            const authnContextDeclRefs = []
            const DeclRefs_inputs = DeclRefs_items.querySelectorAll("input");
            DeclRefs_inputs.forEach(input => {
                if (input.value.trim() !== "") {
                    authnContextDeclRefs.push(input.value);
                }
            });

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
                    "allowCreate": allowCreate.value,
                    "encryptionAlgorithm":encryption_algorithm.value,
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
                    "postBindingAuthnRequest": httpPostBindingAuthnRequest.value,
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
                }
            };


            let isValid = true;
            hasFocused = false;

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



            var selectedrealm = localStorage.getItem('selectedRealm');
            if(alias_input.value){
                // Sending a GET request to check if the plugin exists
                fetch(`${ServerUrl}/admin/realms/${selectedrealm}/identity-provider/instances/${alias_input.value}`, {
                    method: 'GET',
                    headers: {
                        'Authorization': `Bearer ${newAccessToken}`,
                    },
                })

                    // Handling the response of the GET request
                    .then(async checkPluginResponse => {
                        if (checkPluginResponse.ok) {
                            var pluginData = await checkPluginResponse.json();
                            const updatePluginResponse = await fetch(`${ServerUrl}/admin/realms/${selectedrealm}/identity-provider/instances/${alias_input.value}`, {
                                    method: 'PUT',
                                    headers: {
                                        'Authorization': `Bearer ${newAccessToken}`,
                                        'Content-Type': 'application/json',
                                    },
                                    body: JSON.stringify(data),
                                }

                            );
                            localStorage.setItem('pluginData', JSON.stringify(data));



                            // Checking the response status for success
                            if (updatePluginResponse.status === 204 || updatePluginResponse.status === 201) {
                                console.log("Plugin updated successfully.");
                                alert("Plugin updated successfully.");
                                getAllPlugins(newAccessToken,selectedrealm);
                                localStorage.setItem('pluginData', JSON.stringify(data));


                            } else {
                                console.error(`Failed to update/add the plugin. Response: ${updatePluginResponse.statusText}`);
                                console.error("Error Details:", await updatePluginResponse.json());
                                alert("Failed to update the plugin")
                            }
                        } else if (checkPluginResponse.status === 404) {
                            // If the status is 404, the plugin does not exist, so send a POST request
                            return fetch(`${ServerUrl}/admin/realms/${selectedrealm}/identity-provider/instances`, {
                                method: 'POST',
                                headers: {
                                    'Authorization': `Bearer ${newAccessToken}`,
                                    'Content-Type': 'application/json',
                                },
                                body: JSON.stringify(data),
                            })
                                .then(response => {
                                    if (response.ok) {
                                        alert("Plugin added successfully.");

                                        localStorage.setItem('pluginData', JSON.stringify(data));

                                    } else {
                                        console.error('Failed to add plugin:', response.status, response.statusText);
                                        alert("Failed to add plugin");
                                    }
                                })
                                .catch(error => {

                                    console.error('Network error or failed to send request:', error);
                                });


                        } else {
                            // If there is another status, an error occurred

                            console.error(`Failed to retrieve the plugin. Response: ${checkPluginResponse.statusText}`);
                            alert("Failed to retrieve the plugin");
                            throw new Error(`Failed to retrieve the plugin. Response: ${checkPluginResponse.statusText}`);
                        }
                    })

                    // Handling the response of the POST request (if executed)
                    .then(response => {
                        // ... (Additional code that was commented out)
                    })
                    .catch(error => {
                        // ... (Additional code that was commented out)
                    });
            }else
            {console.error('alias_input does not exist')}

            // Setting a form element value to an empty string

        } else {
            console.error("Token is not updated");
        }
    });
});