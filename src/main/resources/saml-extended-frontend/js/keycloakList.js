var accessToken;
const keycloak = new Keycloak({
    url: `${ServerUrl}`,
    realm: `${realm}`,
    clientId: `${clientid}`,
    redirectUri: `${redirectUri}`,
    enableDebug: true,

});


document.getElementById('logout').addEventListener('click', () => {
    window.location.href = `${ServerUrl}/realms/${realm}/protocol/openid-connect/logout?post_logout_redirect_uri=${postLogoutRedirect}&client_id=${clientid}`;
});

keycloak
    .init({ onLoad: 'login-required' })
    .then((authenticated) => {
        if (authenticated) {
            const accessToken = keycloak.token;
            getAllRealms(accessToken);

            const tokenParsed = keycloak.tokenParsed;
            const realmRoles = tokenParsed.realm_access.roles;
            const clientRoles = tokenParsed.resource_access;


            if ((clientRoles && clientRoles['realm-management'] && clientRoles['realm-management'].roles.includes("realm-admin")) || realmRoles.includes("admin")) {
                document.body.style.display = 'block';
            } else {
                alert("User does not have admin role. Access denied.");
                window.location.href = `${ServerUrl}/realms/${realm}/protocol/openid-connect/logout?post_logout_redirect_uri=${post_logout_redirect_uri}&client_id=${clientid}`;
            }
        } else {
            alert("User authentication failed!");
            console.error("User authentication failed!");
        }
    })
    .catch((error) => {
        console.error("Error during Keycloak authentication:", error);

        // Log detailed error information
        if (error.response) {
            console.error("Error Response Data:", error.response.data);
            console.error("Error Response Status:", error.response.status);
            console.error("Error Response Headers:", error.response.headers);
        } else if (error.request) {
            console.error("Error Request Data:", error.request);
        } else {
            console.error("General Error Message:", error.message);
        }

        console.error("Error Configuration:", error.config);

        alert("Could not authenticate the user. Please check console for details.");
    });