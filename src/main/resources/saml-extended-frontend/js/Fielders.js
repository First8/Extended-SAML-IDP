const redirectUriInput = document.getElementById("redirectUri");
const alias_input = document.getElementById("alias");
const add = document.getElementById("submit");
const samlEntityDescriptor = document.getElementById("samlEntityDescriptor");
const import_data = document.getElementById("import");
const edit = document.getElementById("edit");
const Display_Name_input = document.getElementById("displayName");
const Display_Order_input = document.getElementById("displayOrder");
const Service_Provider_Entity_ID_input = document.getElementById("spEntityId");
const Identity_Provider_Entity_ID_input = document.getElementById("idpEntityId");
const Single_Sign_On_Service_URL_input = document.getElementById("ssoServiceUrl");
const Single_Sign_On_Service_URL_inpu_edit = document.getElementById("ssoServiceUrl_edit");
const Single_Logout_Service_URL_input = document.getElementById("sloServiceUrl");
const allowedClockSkew_input = document.getElementById("allowedClockSkew");
const attributeConsumingServiceIndex_input = document.getElementById("attributeConsumingServiceIndex");
const attributeConsumingServiceName_input = document.getElementById("attributeConsumingServiceName");
const authnContextClassRefs_input = document.getElementById("authnContextClassRefs");
const authnContextDeclRefs_input = document.getElementById("authnContextDeclRefs");
const comparison_input = document.getElementById("comparison");
const firstLoginFlow_input = document.getElementById("firstLoginFlow");
const postLoginFlow_input = document.getElementById("postLoginFlow");
const syncMode_input = document.getElementById("syncMode");
const principalType_input = document.getElementById("principalType");
const nameIdPolicy_input = document.getElementById("nameIdPolicy");
const SignatureAlgorithm_input = document.getElementById("SignatureAlgorithm");
const SAMLSignatureKeyName_input = document.getElementById("SAMLSignatureKeyName");
const ValidatingX509Certificates_input = document.getElementById("ValidatingX509Certificates");
const Artifact_Resolution_Endpoint_input = document.getElementById("Artifact_Resolution_Endpoint");
const CharacterSet_input = document.getElementById("CharacterSet");
const Metadata_expires_in_input = document.getElementById("Metadata_expires_in");
const metadataValidUntilPeriod_input = document.getElementById("metadataValidUntilPeriod");
const Linked_Providers_input = document.getElementById("Linked_Providers");
const additionalField_endpoint=document.getElementById("Artifact_Resolution_Endpoint");
const ClassRefs_items = document.getElementById("ClassRefs_items");
const principalAttribute_input=document.getElementById('principalAttribute');
var resultsContainer = document.getElementById('resultsContainer');
var errorMessage = document.getElementById("errorMessage");
var errorMessage_URL = document.getElementById("errorMessage_URL");
var errorMessage_URL_logout = document.getElementById("errorMessage_URL_logout");
var errorMessage_URL_logout = document.getElementById("errorMessage_URL_logout");
var Realms=document.getElementById("Realms");
var encryption_algorithm=document.getElementById("encryption_algorithm");
var storedData;
var samlEntityDescriptor_input=document.getElementById("samlEntityDescriptor")
var  samlEntityDescriptor_errorMessage_URL=document.getElementById("samlEntityDescriptor_errorMessage_URL")

function handleCheckboxValue(checkbox) {
    if (checkbox.checked) {
        checkbox.value = true;
    } else {
        checkbox.value = false;
    }
}

function removeEmptyStrings(obj) {
    for (const key in obj) {
        if (typeof obj[key] === 'string' && obj[key].trim() === "") {
            delete obj[key];
        } else if (typeof obj[key] === 'object' && !Array.isArray(obj[key])) {
            removeEmptyStrings(obj[key]);
        }
    }
}
window.removeEmptyStrings=removeEmptyStrings