


storedData = localStorage.getItem('pluginData');
var pluginData = JSON.parse(storedData);
backchannel.value = pluginData.config.backchannelSupported ? pluginData.config.backchannelSupported : false;
backchannel.addEventListener("change", function () {
    handleCheckboxValue(backchannel);
});


const allowCreate = document.getElementById("allowCreate");
allowCreate.value = pluginData.config.allowCreate ? pluginData.config.allowCreate : false;
allowCreate.addEventListener("change", function () {
    handleCheckboxValue(allowCreate);
});




const httpPostBindingResponse = document.getElementById("httpPostBindingResponse");
httpPostBindingResponse.value = pluginData.config.postBindingResponse ? pluginData.config.postBindingResponse : false;
httpPostBindingResponse.addEventListener("change", function () {
    handleCheckboxValue(httpPostBindingResponse);


});






const httpPostBindingAuthnRequest = document.getElementById("httpPostBindingAuthnRequest");
httpPostBindingAuthnRequest.value = pluginData.config.postBindingAuthnRequest ? pluginData.config.postBindingAuthnRequest : false;
httpPostBindingAuthnRequest.addEventListener("change", function () {
    handleCheckboxValue(httpPostBindingAuthnRequest);

});

const httpPostBindingLogout = document.getElementById("httpPostBindingLogout");
httpPostBindingLogout.value = pluginData.config.postBindingLogout ? pluginData.config.postBindingLogout : false;
httpPostBindingLogout.addEventListener("change", function () {
    handleCheckboxValue(httpPostBindingLogout);

});


const wantAssertionsSigned = document.getElementById("wantAssertionsSigned");
wantAssertionsSigned.value = pluginData.config.wantAssertionsSigned ? pluginData.config.wantAssertionsSigned : false;
wantAssertionsSigned.addEventListener("change", function () {
    handleCheckboxValue(wantAssertionsSigned);

});


const wantAssertionsEncrypted = document.getElementById("wantAssertionsEncrypted");
wantAssertionsEncrypted.value = pluginData.config.wantAssertionsEncrypted ? pluginData.config.wantAssertionsEncrypted : false;
wantAssertionsEncrypted.addEventListener("change", function () {
    handleCheckboxValue(wantAssertionsEncrypted);

});


const forceAuthentication = document.getElementById("forceAuthentication");
forceAuthentication.value = pluginData.config.forceAuthn ? pluginData.config.forceAuthn : false;
forceAuthentication.addEventListener("change", function () {
    handleCheckboxValue(forceAuthentication);
});



const signMetadata = document.getElementById("signMetadata");
signMetadata.value = pluginData.config.signSpMetadata ? pluginData.config.signSpMetadata : false
signMetadata.addEventListener("change", function () {
    handleCheckboxValue(signMetadata);

});


const passSubject = document.getElementById("passSubject");
passSubject.value = pluginData.config.loginHint ? pluginData.config.loginHint : false;
passSubject.addEventListener("change", function () {
    handleCheckboxValue(passSubject);

});


const storeToken = document.getElementById("storeToken");
storeToken.value = pluginData.storeToken ? pluginData.storeToken : false;
storeToken.addEventListener("change", function () {
    handleCheckboxValue(storeToken);

});


const storedTokensReadable = document.getElementById("storedTokensReadable");
storedTokensReadable.value = pluginData.addReadTokenRoleOnCreate ? pluginData.addReadTokenRoleOnCreate : false;
storedTokensReadable.addEventListener("change", function () {
    handleCheckboxValue(storedTokensReadable);

});


const trustEmail = document.getElementById("trustEmail");
trustEmail.value = pluginData.trustEmail ? pluginData.trustEmail : false;
trustEmail.addEventListener("change", function () {
    handleCheckboxValue(trustEmail);

});




const accountLinkingOnly = document.getElementById("accountLinkingOnly");
accountLinkingOnly.value = pluginData.linkOnly ? pluginData.linkOnly : false;
accountLinkingOnly.addEventListener("change", function () {
    handleCheckboxValue(accountLinkingOnly);

});


const hideLoginPage = document.getElementById("hideLoginPage");
hideLoginPage.value = pluginData.config.hideOnLoginPage ? pluginData.config.hideOnLoginPage : false;
hideLoginPage.addEventListener("change", function () {
    handleCheckboxValue(hideLoginPage);

});


var SignatureAlgorithm = document.getElementById("SignatureAlgorithm");
var SAMLSignatureKeyName = document.getElementById("SAMLSignatureKeyName");

const wantAuthnRequestsSigned = document.getElementById("wantAuthnRequestsSigned");
wantAuthnRequestsSigned.value = pluginData.config.wantAuthnRequestsSigned ? pluginData.config.wantAuthnRequestsSigned : false;
wantAuthnRequestsSigned.addEventListener("change", function () {
    if (wantAuthnRequestsSigned.checked) {
        wantAuthnRequestsSigned.value = true;
        SignatureAlgorithm.removeAttribute("disabled");
        SAMLSignatureKeyName.removeAttribute("disabled");
        encryption_algorithm.removeAttribute("disabled");
        console.log(`wantAuthnRequestsSigned_value: ${wantAuthnRequestsSigned.value}`)

    }
    else {
        wantAuthnRequestsSigned.value = false;
        console.log(`wantAuthnRequestsSigned_value: ${wantAuthnRequestsSigned.value}`)
        SignatureAlgorithm.setAttribute("disabled", "true");
        SAMLSignatureKeyName.setAttribute("disabled", "true");
        encryption_algorithm.setAttribute("disabled", "true");


        ;
    }
});

const ArtifactResolutionService_in_metadata = document.getElementById("ArtifactResolutionService_in_metadata");
ArtifactResolutionService_in_metadata.value = pluginData.config.includeArtifactResolutionServiceMetadata ? pluginData.config.includeArtifactResolutionServiceMetadata : false;
ArtifactResolutionService_in_metadata.addEventListener("change", function () {
    handleCheckboxValue(ArtifactResolutionService_in_metadata);

});

document.addEventListener("DOMContentLoaded", function () {
    const deleteButtonsClassRefs = document.querySelectorAll(".delete");
    const addButtonClassRefs = document.getElementById("addClassRefs");
    const ClassRefs_items = document.getElementById("ClassRefs_items");

    deleteButtonsClassRefs.forEach(function (button) {
        button.style.display = "inline";
    });

    addButtonClassRefs.addEventListener("click", function (e) {
        deleteButtonsClassRefs.forEach(function (button) {
            button.style.display = "inline";
        });

        const newItem = document.createElement("div");
        newItem.className = "next-referral col-4";
        newItem.innerHTML = '<input name="textinputClassRefs" type="text" class="input_text">';
        ClassRefs_items.appendChild(newItem);
    });

    document.body.addEventListener("click", function (e) {
        if (e.target.classList.contains("delete")) {
            const items = ClassRefs_items.querySelectorAll(".next-referral");
            if (items.length > 0) {
                items[items.length - 1].remove();
                deleteButtonsClassRefs.forEach(function (button, index) {
                    if (index === items.length - 1) {
                        button.style.display = "inline";
                    }
                });
            }
        }
    });
});

document.addEventListener("DOMContentLoaded", function () {
    const deleteButtonsDeclRefs = document.querySelectorAll(".delete1");
    const addButtonDeclRefs = document.getElementById("addDeclRefs");
    const DeclRefs_items = document.getElementById("DeclRefs_items");

    deleteButtonsDeclRefs.forEach(function (button) {
        button.style.display = "inline";
    });

    addButtonDeclRefs.addEventListener("click", function (e) {
        deleteButtonsDeclRefs.forEach(function (button) {
            button.style.display = "inline";
        });

        const newItem = document.createElement("div");
        newItem.className = "next-referral col-4";
        newItem.innerHTML = '<input name="textinputDeclRefs" type="text" class="input_text">';
        DeclRefs_items.appendChild(newItem);
    });

    document.body.addEventListener("click", function (e) {
        if (e.target.classList.contains("delete1")) {
            const items = DeclRefs_items.querySelectorAll(".next-referral");
            if (items.length > 0) {
                items[items.length - 1].remove();
                deleteButtonsDeclRefs.forEach(function (button, index) {
                    if (index === items.length - 1) {
                        button.style.display = "inline";
                    }
                });
            }
        }
    });
});



var validateSignatures = document.getElementById("validateSignatures");
var additionalField1 = document.getElementById("ValidatingX509Certificates");
validateSignatures.value = pluginData.config.validateSignature ? pluginData.config.validateSignature : false;


validateSignatures.addEventListener("change", function () {
    if (validateSignatures.checked) {
        validateSignatures.value = true;
        console.log(`validateSignatures_value: ${validateSignatures.value}`)
        additionalField1.removeAttribute("disabled");


    }
    else {
        validateSignatures.value = false;
        console.log(`validateSignatures_value: ${validateSignatures.value}`)
        additionalField1.setAttribute("disabled", "true");
        additionalField1.value = '';
        ;
    }
});

var Artifact_Resolution = document.getElementById("Artifact_Resolution");
Artifact_Resolution.value = pluginData.config.artifactResolution ? pluginData.config.artifactResolution : false;

Artifact_Resolution.addEventListener("change", function () {
    if (Artifact_Resolution.checked) {
        Artifact_Resolution.value = true;
        console.log(`Artifact_Resolution_value: ${Artifact_Resolution.value}`)
        additionalField_endpoint.removeAttribute("disabled");

    }
    else {
        Artifact_Resolution.value = false;
        console.log(`Artifact_Resolution_value: ${Artifact_Resolution.value}`)
        additionalField_endpoint.setAttribute("disabled", "true");
        additionalField_endpoint.value = '';

        ;
    }
}
);


const Sign_Artifact_Resolution_Request = document.getElementById("Sign_Artifact_Resolution_Request");
Sign_Artifact_Resolution_Request.value = pluginData.config.signArtifactResolutionRequest ? pluginData.config.signArtifactResolutionRequest : false;
Sign_Artifact_Resolution_Request.addEventListener("change", function () {
    handleCheckboxValue(Sign_Artifact_Resolution_Request);

});

const ArtifactResolution_via_HTTP_ARTIFACT = document.getElementById("ArtifactResolution_via_HTTP_ARTIFACT");
ArtifactResolution_via_HTTP_ARTIFACT.value = pluginData.config.artifactResolutionHTTPArtifact ? pluginData.config.artifactResolutionHTTPArtifact : false;
ArtifactResolution_via_HTTP_ARTIFACT.addEventListener("change", function () {
    handleCheckboxValue(ArtifactResolution_via_HTTP_ARTIFACT);

});




const Artifact_Resolution_with_SOAP = document.getElementById("Artifact_Resolution_with_SOAP");
Artifact_Resolution_with_SOAP.value = pluginData.config.artifactResolutionSOAP ? pluginData.config.artifactResolutionSOAP : false;
Artifact_Resolution_with_SOAP.addEventListener("change", function () {
    handleCheckboxValue(Artifact_Resolution_with_SOAP);

});



const Artifact_Resolution_with_XML_header = document.getElementById("Artifact_Resolution_with_XML_header");
Artifact_Resolution_with_XML_header.value = pluginData.config.artifactResolutionWithXmlHeader ? pluginData.config.artifactResolutionWithXmlHeader : false;
Artifact_Resolution_with_XML_header.addEventListener("change", function () {
    handleCheckboxValue(Artifact_Resolution_with_XML_header);

});


const Mutual_TLS = document.getElementById("Mutual_TLS");
Mutual_TLS.value = pluginData.config.mutualTls ? pluginData.config.mutualTls : false;
Mutual_TLS.addEventListener("change", function () {
    handleCheckboxValue(Mutual_TLS);

});
const enabled = document.getElementById("enabled");
enabled.value = pluginData.enabled ? pluginData.enabled : false;
enabled.addEventListener("change", function () {
    handleCheckboxValue(enabled);

});

principalType_input.addEventListener('change', function () {
    console.log(principalType_input.value)
    if (principalType_input.value == "ATTRIBUTE" || principalType_input.value == "FRIENDLY_ATTRIBUTE") {
        principalAttribute_input.removeAttribute("disabled");

    } else {
        principalAttribute_input.value = '';
        principalAttribute_input.setAttribute("disabled", "true");

    }
});