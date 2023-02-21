# keycloak-conditional-otp-login-attempts-based
Create custom KEYCLOAK authentication provider which allow user to configurable login attempts with MFA verification

## build

The Keycloak SPI is very stable but always make sure that Keycloak SPI dependencies and your Keycloak server versions match. Keycloak SPI dependencies version is configured in `pom.xml` in the `keycloak.version` property.

To build the project execute the following command:

```bash
mvn package
```

## deploy

Assuming `$KEYCLOAK_HOME` is pointing to you Keycloak installation.
 
