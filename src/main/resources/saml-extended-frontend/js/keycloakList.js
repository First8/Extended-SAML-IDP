var accessToken;
const keycloak = Keycloak({
    url: `${ServerUrl}`,
    realm: `${realm}`,
    clientId: `${clientid}`,
    redirectUri: `${redirectUri}`,


});

document.getElementById('logout').addEventListener('click', () => {
    window.location.href = `${ServerUrl}/realms/${realm}/protocol/openid-connect/logout?post_logout_redirect_uri=${postLogoutRedirect}&client_id=${clientid}`;
});

keycloak
    .init({ onLoad: 'login-required' })
    .then((authenticated) => {
        if (authenticated) {
            accessToken = keycloak.token;
            // getAllPlugins(accessToken);
            getAllRealms(accessToken)
            const tokenParsed = keycloak.tokenParsed;
            const realmroles = tokenParsed.realm_access.roles;
            const clientroles = tokenParsed.resource_access;

            if ((clientroles && clientroles['realm-management'] && clientroles['realm-management'].roles.includes("realm-admin")) || realmroles.includes("admin")) {
                document.body.style.display = 'block';
            } else {

                alert("User does not have admin role. Access denied.");
                window.location.href = `${ServerUrl}/realms/${realm}/protocol/openid-connect/logout?post_logout_redirect_uri=${post_logout_redirect_uri}&client_id=${clientid}`;

            }
        }

        else {

            alert("User authentication failed!");

        }
    })
    .catch(() => {
        alert("Could not authenticate the user!");
    });
