
let hasFocused = false;
function handleInvalidInput(inputElement, errorMessageElement, message) {
    inputElement.classList.remove('input_text');
    inputElement.classList.add('red-border');
    if (!hasFocused) {
        inputElement.focus();
        hasFocused = true;
    }
    errorMessageElement.textContent = message;
}
window.handleInvalidInput=handleInvalidInput
function handleValidInput(inputElement, errorMessageElement, message) {
    inputElement.classList.remove('red-border');
    inputElement.classList.add('input_text');
    errorMessageElement.textContent = message;
}
window.handleValidInput=handleValidInput
function isValidUrl(url) {
    return url && url.startsWith("https://");
}
window.isValidUrl=isValidUrl