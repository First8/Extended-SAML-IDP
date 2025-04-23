<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8"/>
    <meta name="viewport" content="width=device-width, initial-scale=1"/>
    <meta name="theme-color" content="#000000"/>
    <title>SAML for Keycloak WebAdmin</title>
</head>
<body>
<noscript>You need to enable JavaScript to run this app.</noscript>
<input id="backend-url" type="hidden" value="${backendUrl}" disabled/>
<script>
    var backendUrl = document.getElementById("backend-url").value;
    localStorage.setItem("backendUrl", backendUrl);
</script>
<script src=./js/Config></script>
<div id="root"></div>
</body>
</html>
