package com.example.iam.pre_update_password_action_service.service;



import java.util.List;
import java.util.Locale;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import com.example.iam.pre_update_password_action_service.dto.ActionRequest;
import com.example.iam.pre_update_password_action_service.dto.ActionResponse;

/**
 * The corporate password policy.
 * Nothing here ever logs the password. Only the decision is logged.
 */
@Service
public class PasswordPolicyValidator {

    private static final Logger LOG = LoggerFactory.getLogger(PasswordPolicyValidator.class);

    private static final String USERNAME_CLAIM = "http://wso2.org/claims/username";
    private static final String PLAIN_TEXT = "PLAIN_TEXT";
    private static final String TYPE_PASSWORD = "PASSWORD";

    private final List<String> forbiddenTokens;
    private final int minLength;
    private final boolean failClosedOnHash;

    public PasswordPolicyValidator(
            @Value("${password-policy.forbidden-tokens}") List<String> forbiddenTokens,
            @Value("${password-policy.min-length:8}") int minLength,
            @Value("${password-policy.fail-closed-on-hash:true}") boolean failClosedOnHash) {
        this.forbiddenTokens = forbiddenTokens;
        this.minLength = minLength;
        this.failClosedOnHash = failClosedOnHash;
    }

    public ActionResponse validate(ActionRequest request) {

        // ---- 1. Is the payload usable at all? ----
        ActionRequest.Event event = request.event();
        if (event == null || event.user() == null || event.user().updatingCredential() == null) {
            LOG.warn("Rejecting [requestId={}]: event.user.updatingCredential missing",
                    request.requestId());
            return ActionResponse.error("invalid_request",
                    "The event.user.updatingCredential object is missing.");
        }

        ActionRequest.UpdatingCredential credential = event.user().updatingCredential();
        String flow = event.initiatorType() + "/" + event.action();

        if (!TYPE_PASSWORD.equalsIgnoreCase(credential.type())) {
            return ActionResponse.error("invalid_credential",
                    "Only credentials of type PASSWORD are supported.");
        }

        // ---- 2. Can we inspect the password? ----
        // A SHA-256 digest cannot be searched for the substring "wso2",
        // so hashed sharing makes these rules impossible to evaluate.
        if (!PLAIN_TEXT.equalsIgnoreCase(credential.format())) {
            if (failClosedOnHash) {
                LOG.error("Cannot evaluate policy [requestId={}, flow={}]: password shared as {}. "
                                + "Set the action's password sharing format to plain text.",
                        request.requestId(), flow, credential.format());
                return ActionResponse.error("unsupported_password_format",
                        "This service needs the password in plain text.");
            }
            LOG.warn("Skipping policy [requestId={}, flow={}]: password shared as {}",
                    request.requestId(), flow, credential.format());
            return ActionResponse.success();
        }

        String password = credential.value();
        if (password == null || password.isEmpty()) {
            return ActionResponse.error("invalid_credential", "The password value is empty.");
        }

        String lower = password.toLowerCase(Locale.ROOT);
        String username = extractUsername(event.user());

        // ---- 3. The rules ----
        if (password.length() < minLength) {
            return reject(request, flow, "password_too_short",
                    "The password must be at least " + minLength + " characters long.");
        }

        for (String token : forbiddenTokens) {
            if (token != null && !token.isBlank()
                    && lower.contains(token.toLowerCase(Locale.ROOT))) {
                return reject(request, flow, "forbidden_token_in_password",
                        "The password must not contain the company term '" + token + "'.");
            }
        }

        if (username != null && !username.isBlank() && containsIdentifier(lower, username)) {
            return reject(request, flow, "username_in_password",
                    "The password must not contain your username.");
        }

        LOG.info("Password accepted [requestId={}, flow={}, userId={}]",
                request.requestId(), flow, event.user().id());
        return ActionResponse.success();
    }

    private ActionResponse reject(ActionRequest request, String flow,
                                  String reason, String description) {
        LOG.info("Password rejected [requestId={}, flow={}, reason={}]",
                request.requestId(), flow, reason);
        return ActionResponse.failed(reason, description);
    }

    /**
     * Checks the username, and when it looks like an email address its local
     * part too, so "john.doe@corp.com" also blocks "john.doe123".
     */
    private boolean containsIdentifier(String lowerPassword, String username) {
        String lowerUsername = username.toLowerCase(Locale.ROOT);
        if (lowerPassword.contains(lowerUsername)) {
            return true;
        }
        int at = lowerUsername.indexOf('@');
        return at > 2 && lowerPassword.contains(lowerUsername.substring(0, at));
    }

    /** Pulls the username out of the shared claims, if it was shared at all. */
    private String extractUsername(ActionRequest.User user) {
        if (user.claims() == null) {
            return null;
        }
        for (ActionRequest.Claim claim : user.claims()) {
            if (USERNAME_CLAIM.equals(claim.uri())) {
                return firstStringValue(claim.value());
            }
        }
        return null;
    }

    /** Claim values are either a string or a JSON array of strings. */
    private String firstStringValue(Object value) {
        if (value instanceof String s) {
            return s;
        }
        if (value instanceof List<?> list && !list.isEmpty() && list.get(0) != null) {
            return list.get(0).toString();
        }
        return null;
    }
}
