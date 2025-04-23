const ServerUrl = window.location.protocol+"//" + window.location.host;
console.log(ServerUrl)
const clientid = 'frontend';
const postLogoutRedirect = `${ServerUrl}/realms/master/samlconfig/pages/realm`;
const redirectUri = `${ServerUrl}/realms/master/samlconfig/pages/list`;
const editplugin=`${ServerUrl}/realms/master/samlconfig/pages/editplugin`;
const addplugin=`${ServerUrl}/realms/master/samlconfig/pages/addplugin`;
const realm = localStorage.getItem('realm_input');
localStorage.setItem('ServerUrl', ServerUrl);
localStorage.setItem('postLogoutRedirect', postLogoutRedirect);
localStorage.setItem('redirectUri', redirectUri);
localStorage.setItem('addplugin', addplugin);
localStorage.setItem('clientid', clientid);
localStorage.setItem('realm', realm);
