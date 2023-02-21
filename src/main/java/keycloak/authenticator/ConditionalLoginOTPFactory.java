package keycloak.authenticator;

import java.util.ArrayList;
import java.util.List;

import org.keycloak.Config;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.AuthenticatorFactory;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.provider.ProviderConfigProperty;

/**
 * @author ashan on 2023-02-20
 */
public class ConditionalLoginOTPFactory implements AuthenticatorFactory {

    public static final String PROVIDER_ID = "login-counter-authenticator";

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String getDisplayType() {
        return "Login Counter Authenticator";
    }

    @Override
    public String getHelpText() {
        return "Make  OTP mandatory for users after certain initial logins";
    }

    @Override
    public String getReferenceCategory() {
        return "otp";
    }

    @Override
    public boolean isConfigurable() {
        return true;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return true;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        List<ProviderConfigProperty> providerConfigList = new ArrayList<>();
        providerConfigList.add(new ProviderConfigProperty("loginCount", "Login count",
                "Grace period login count to make OTP mandatory", ProviderConfigProperty.STRING_TYPE, 3));
        return providerConfigList;
    }

    @Override
    public Authenticator create(KeycloakSession keycloakSession) {
        return new ConditionalLoginCountAuthenticator();
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory keycloakSessionFactory) {

    }

    @Override
    public void close() {

    }
}
