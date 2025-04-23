const clientid = 'frontend';
const postLogoutRedirect = 'https://keycloak.cloud.first8.nl/samlconfig/pages/realm.html';
const ServerUrl = 'https://keycloak.cloud.first8.nl';
const redirectUri = 'https://keycloak.cloud.first8.nl/samlconfig/pages/list.html';
const realm = localStorage.getItem('realm_input');
console.log(realm)
const editplugin='https://keycloak.cloud.first8.nl/samlconfig/pages/editplugin.html';
const addplugin='https://keycloak.cloud.first8.nl/samlconfig/pages/addPlugin.html';
localStorage.setItem('ServerUrl', ServerUrl);
localStorage.setItem('postLogoutRedirect', postLogoutRedirect);
localStorage.setItem('redirectUri', redirectUri);
localStorage.setItem('addplugin', addplugin);
localStorage.setItem('clientid', clientid);
localStorage.setItem('realm', realm);
