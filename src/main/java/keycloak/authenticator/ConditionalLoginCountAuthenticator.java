package keycloak.authenticator;

import java.util.Collections;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.Authenticator;
import org.keycloak.models.AuthenticatorConfigModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.SubjectCredentialManager;
import org.keycloak.models.UserModel;
import org.keycloak.models.credential.OTPCredentialModel;

public class ConditionalLoginCountAuthenticator implements Authenticator {
    private static final Logger logger = Logger.getLogger(ConditionalLoginCountAuthenticator.class);
    private static final String LOGIN_COUNT_BASED_OTP_CONDITIONAL_USER_ATTRIBUTE = "login_count_based_otp_conditional";
    private static final String OTP_FREE_CONSUMED_LOGINS_USER_ATTRIBUTE = "opt_free_consumed_logins";

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        AuthenticatorConfigModel config = context.getAuthenticatorConfig();
        RealmModel realm = context.getRealm();
        UserModel user = context.getUser();

        int allowedMaxOTPFreeCount = Integer.parseInt(config.getConfig().get("loginCount"));
        int otpFreeConsumedLogins = 0;
        String userConsumedLogins = user.getFirstAttribute(OTP_FREE_CONSUMED_LOGINS_USER_ATTRIBUTE);
        if (userConsumedLogins != null) {
            otpFreeConsumedLogins = Integer.parseInt(userConsumedLogins);
        }

        if (otpFreeConsumedLogins < allowedMaxOTPFreeCount) {
            logger.infof(
                "User OTP signin is skipped. Realm %s OTP free consumable login %s but user %s logged consumed logins %s",
                realm.getName(), allowedMaxOTPFreeCount, user.getUsername(), otpFreeConsumedLogins);
            user.setAttribute(LOGIN_COUNT_BASED_OTP_CONDITIONAL_USER_ATTRIBUTE, Collections.singletonList("skip"));
            user.setAttribute(OTP_FREE_CONSUMED_LOGINS_USER_ATTRIBUTE,
            Collections.singletonList(Integer.toString(++otpFreeConsumedLogins)));
        } else {
            SubjectCredentialManager credentialManager = user.credentialManager();
            if (!credentialManager.isConfiguredFor(OTPCredentialModel.TYPE)) {
                user.addRequiredAction(UserModel.RequiredAction.CONFIGURE_TOTP);
            }
            user.setAttribute(LOGIN_COUNT_BASED_OTP_CONDITIONAL_USER_ATTRIBUTE, Collections.singletonList("force"));
        }
        context.success();

    }

    @Override
    public void action(AuthenticationFlowContext context) {

    }

    @Override
    public boolean requiresUser() {
        return true;
    }

    @Override
    public boolean configuredFor(KeycloakSession session, RealmModel realm, UserModel user) {
        return true;
    }

    @Override
    public void setRequiredActions(KeycloakSession session, RealmModel realm, UserModel user) {

    }

    @Override
    public void close() {

    }

}
