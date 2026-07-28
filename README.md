# Table of contents

1. [Extended SAML Identity Provider](#extended-saml-identity-provider)
2. [Building and installing](#building)
3. [Frontend-Keycloak-Saml-Extended](#frontend-keycloak-saml-extended)

<a name="extended-saml-identity-provider"></a>

# Extended SAML Identity Provider

This extension implements a keycloak Identity Provider (IDP) that can issue direct (synchronous) SAML requests to
external providers, like eHerkenning or DigiD, which keycloak itself does not support (yet).

In addition, the Extended SAML Identity Provider adds support for Encrypted Attributes. These are used by eHerkenning.

## Configuration

For Keycloak up to version 20.x, the Extended SAML Identity Provider can be added to a realm using the standard keycloak
Admin Console, provided you set the Admin Theme to `keycloak` to indicate you want to use the v1 (legacy) UI.

In keycloak versions 21.x and higher, the legacy UI is no longer available; you can still edit most settings of the
provider in the Admin Console if it was created using the legacy UI, but some of the specialized settings are hidden.

To manage the Extended SAML IDP in new keycloak releases you can use the REST API provided by keycloak in combination
with a custom frontend.

## Upgrading

The steps to upgrade to a new Keycloak minor version are as follows (also: the steps are analogous in case of a new major version):

1. Pull the branch corresponding to the most recent Keycloak minor version that already exists in the repository.

2. Create a new branch from there, corresponding to the next minor version: `upgrade-to-{a}.{b+1}`, e.g. `upgrade-to-27.2`.

3. Update `<keycloak.version>` in the pom.xml to the most recent patch version of the relevant minor version.

4. Create a patch for the `.java` files corresponding to those in this repository, based on the [official Keycloak repository's](https://github.com/keycloak/keycloak) files and branches:

```
cd patch-tool
./patch.sh archive/release/{a}.{b} archive/release/{a}.{b+1} 
#E.g. a=27, b=1. Could be {a+1}.0 instead of {a}.{b+1}, or (one of) the releases may not be archived yet.
```

If you have trouble creating the patch, consult the Readme in the `/patch-tool` directory for more details.

5. Apply the patch.

    * Many manual actions are needed, as the line numbers do not correspond.
    * Don't remove our custom code unless 100% sure that it is unnecessary. Preferably keep that sort of clean-up out of this upgrade-PR though, to retain overview.
    * If a change references a Keycloak class that doesn't have an equivalent (same name) in this repository, just import it, instead of adding it to this repository.
    * If a method (/signature) is changed, it is probably due to deprecation. You could look up the documentation for the method that got replaced to make sure.
    * You might understand the rationale for changes in the commit message corresponding to that change, and/or the issue that is linked from that commit message.

6. Fix bugs until you can build a jar normally with `mvn clean package`.

7. (Optionally) first verify that your SAML IDP connections work with the old Keycloak version and/or old jar.

8. (Optionally) do the same tests as the PR reviewer will do in their steps below.

9. Create a branch, e.g. `27.2.x-once-PR-merged`, from the previous minor, e.g. `27.1` here.

10. Push both new branches: `{a}.{b+1}.x-once-PR-merged` and `upgrade-to-{a}.{b+1}`

11. Make a PR from `upgrade-to-{a}.{b+1}` into `{a}.{b+1}.x-once-PR-merged`.



### For the Pull Request Reviewer

12. Run the new code from the PR through Test classes, not only `<Response>` but also `<ArtifactResponse>`.

    * (Preferably) don't just test the auto-generated mock (Artifact)Responses, 
      but also real-world (Artifact)Responses that you can copy into the test resource folder and reference in Test classes (don't commit those changes).

13. Build the jar from your new branch and try logging in with the SAML IDP connections in your test environment.

    * A Keycloak upgrade might be needed beforehand.
    * If you normally only receive `<Response>` or `<ArtifactResponse>`, set up a connection to test the other type (you may skip this if you already tested real-world examples of that type in Test classes)
    * Also test with mappers and encryption.

### After the PR merge

    * Rename branch `{a}.{b+1}.x-once-PR-merged` to just `{a}.{b+1}.x`, e.g. `27.2.x`.
    * Remove branch `upgrade-to-{a}.{b+1}`.

10. Change the repository's main branch to the most recent version branch, `{a}.{b+1}.x`.

## Building

```mvn clean package```

This produces `target/idp-saml2-extended-____.jar`

## Installing

### Installing in containerized keycloak (Wildfly)

To install the plugin for development, simply add the `jar` to the `deployments` directory of Keycloak and start it
using  `standalone.sh|bat`. The plugin will be loaded automatically.

### Installing in containerized keycloak (Quarkus)

To install the plugin for development, add the `jar` to the `providers` directory.

A `Dockerfile` would look similar to this:

```dockerfile
FROM quay.io/keycloak/keycloak:20.0.5 as builder

# ...

COPY --chown=keycloak:root idp-saml2-extended-*.jar /opt/keycloak/providers

RUN /opt/keycloak/bin/kc.sh build

FROM quay.io/keycloak/keycloak:20.0.5

COPY --from=builder /opt/keycloak/lib/quarkus/ /opt/keycloak/lib/quarkus/
WORKDIR /opt/keycloak

COPY --chown=keycloak:root idp-saml2-extended-*.jar /opt/keycloak/providers

CMD [\
        "start","--optimized" \
        ]
```

## Frontend-Keycloak-Saml-Extended

### Set Up Keycloak Client:
- Add a new client for the "master" Realm and Any Other Realm You Wish to Log In Through.
- Set the "Client ID" to "saml-extended".
- Configure other settings as needed:
  - Client Authentication: Off
  - Authorization: Off
  - Valid Redirect URIs: `{keycloak-server}/realms/master/samlconfig/pages/*`
  - Valid Post Logout Redirect URIs: `{keycloak-server}/realms/master/samlconfig/pages/realm`
  - Web Origins: `*`
- Click "Save".
  - Front channel logout: On
  - Front-channel logout URL: `{keycloak-server}/realms/master/samlconfig/pages/realm`
  - Front-channel logout session required: On
- Click "Save".

### Add Saml Theme to Keycloak(optional)
- Copy the `saml-frontend-theme` folder.
- Navigate to the themes folder in your Keycloak installation directory. (`\keycloak-directory}\themes`)
- Paste the `saml-frontend-theme` into the themes folder.
- To apply the changes, restart Keycloak with the following command:  
  `./kc.bat start-dev --spi-theme-welcome-theme=saml-frontend-theme`
### Accessing The Frontend:
- (with theme): Open a web browser and navigate to Keycloak welcome page en look for "Saml extended plugin configuration" in the menu and open it.
- (without theme): Go to: {keycloak-server}/realms/master/samlconfig/pages/realm
- After navigating to the browser and opening the specified link, you'll be prompted to write the realm name you want to log in through.
- Choose whichever realm you want to log in to.
- Log in using an admin user account. If you want to log in through a non-master realm, you must assign the "realm-management realm-admin" role to the user you want to log in with.

### To Make the Theme Work:
You need to add `--spi-theme-welcome-theme=saml-frontend-theme` to your Keycloak configuration.
- Adding as Command-Line Argument:
  ```sh
  ./kc.bat start-dev --spi-theme-welcome-theme=saml-frontend-theme

### Access Restrictions
- The admin located in the "master" realm is authorized to add, edit, and delete the IDP (Identity Provider) across all realms
- an admin located in another realm, for example, "other realm," is only authorized to edit and delete their realm's IDP (Identity Provider)
