
add.addEventListener('click', () => {

    var authnContextClassRefs = []
    const ClassRefs_inputs = ClassRefs_items.querySelectorAll("input");
    ClassRefs_inputs.forEach(input => {
        if (input.value.trim() !== "") {
            authnContextClassRefs.push(input.value);
        }
    });
    console.log(authnContextClassRefs);
    const authnContextDeclRefs = []
    const DeclRefs_inputs = DeclRefs_items.querySelectorAll("input");
    DeclRefs_inputs.forEach(input => {
        if (input.value.trim() !== "") {
            authnContextDeclRefs.push(input.value);
        }
    });
    console.log(authnContextDeclRefs);
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
            "encryptionAlgorithm":encryption_algorithm.value,
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
            "linkedProviders": Linked_Providers_input.value
        }
    };

    if (!alias) {
        alias_input.classList.remove('input_text');
        alias_input.classList.add('red-border');
        console.log(alias_input.value);
        alias_input.focus();
        errorMessage.textContent = "Required field !";


        Single_Logout_Service_URL_input.classList.remove('red-border');
        Single_Logout_Service_URL_input.classList.add('input_text');
        errorMessage_URL_logout.textContent = "";

        Single_Sign_On_Service_URL_input.classList.remove('red-border');
        Single_Sign_On_Service_URL_input.classList.add('input_text');
        errorMessage_URL.textContent = "";


        return; // Exit the function if alias_input is empty
    }

    // Check if Single_Sign_On_Service_URL is empty
    if (!Single_Sign_On_Service_URL) {
        Single_Sign_On_Service_URL_input.classList.remove('input_text');
        Single_Sign_On_Service_URL_input.classList.add('red-border');
        Single_Sign_On_Service_URL_input.focus();
        errorMessage_URL.textContent = "Required field !";

        alias_input.classList.remove('red-border');
        alias_input.classList.add('input_text');
        errorMessage.textContent = "";

        Single_Logout_Service_URL_input.classList.remove('red-border');
        Single_Logout_Service_URL_input.classList.add('input_text');
        errorMessage_URL_logout.textContent = "";

        return; // Exit the function if Single_Sign_On_Service_URL is empty
    }

    if (!Single_Sign_On_Service_URL_input.checkValidity() || !Single_Sign_On_Service_URL_input.value.startsWith("https://")) {
        Single_Sign_On_Service_URL_input.classList.remove('input_text');
        Single_Sign_On_Service_URL_input.classList.add('red-border');
        Single_Sign_On_Service_URL_input.focus();
        errorMessage_URL.textContent = "Enter a valid URL !";

        Single_Logout_Service_URL_input.classList.remove('red-border');
        Single_Logout_Service_URL_input.classList.add('input_text');
        errorMessage_URL_logout.textContent = "";

        alias_input.classList.remove('red-border');
        alias_input.classList.add('input_text');
        errorMessage.textContent = "";
        return


    }
    if (!Single_Logout_Service_URL_input.checkValidity() || (Single_Logout_Service_URL_input.value && !Single_Logout_Service_URL_input.value.startsWith("https://"))) {
        Single_Logout_Service_URL_input.classList.remove('input_text');
        Single_Logout_Service_URL_input.classList.add('red-border');
        Single_Logout_Service_URL_input.focus();
        errorMessage_URL_logout.textContent = "Enter a valid URL !";



        Single_Sign_On_Service_URL_input.classList.remove('red-border');
        Single_Sign_On_Service_URL_input.classList.add('input_text');
        errorMessage_URL.textContent = "";

        alias_input.classList.remove('red-border');
        alias_input.classList.add('input_text');
        errorMessage.textContent = "";
        return
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
    console.log(data);

    // Update token and execute the following code when the token is successfully updated 
    keycloak.updateToken(300).then((bool) => {
        if (bool) {

            // Code to be executed after token update 
            var newAccessToken = keycloak.token;
            if (!alias && !Single_Sign_On_Service_URL) {
                alias_input.classList.remove('input_text');
                alias_input.classList.add('red-border');
                Single_Sign_On_Service_URL_input.classList.remove('input_text');
                Single_Sign_On_Service_URL_input.classList.add('red-border');
                console.log(alias_input.value);
                alias_input.focus();
                errorMessage.textContent = "Required field !";
                errorMessage_URL.textContent = "Required field !";
                return; // Exit the function if alias_input is empty
            }
          
           var selectedrealm= localStorage.getItem('selectedRealm');
           console.log(selectedrealm);
            // Sending a GET request to check if the plugin exists 
            fetch(`${ServerUrl}/admin/realms/${selectedrealm}/identity-provider/instances/${alias}`, {
                method: 'GET',
                headers: {
                    'Authorization': ` Bearer ${newAccessToken}`, // Fix here
                },
            })
                .then(async checkPluginResponse => {
                    if (checkPluginResponse.ok) {
                        alias_input.classList.remove('input_text');
                        alias_input.classList.add('red-border');
                        alias_input.focus();
                        errorMessage.textContent = ("Choose a unique *alias* that does not exist");
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
                            window.location.href =`${editplugin}`;
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
});
