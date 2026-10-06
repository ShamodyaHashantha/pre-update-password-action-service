package com.example.iam.pre_update_password_action_service.dto;

import com.fasterxml.jackson.annotation.JsonInclude;

/**
 * The only three answers IS understands.
 * Null fields are dropped, so a success response serialises
 * to exactly {"actionStatus":"SUCCESS"}.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ActionResponse(
        String actionStatus,
        String failureReason,
        String failureDescription,
        String errorMessage,
        String errorDescription) {

    public static ActionResponse success() {
        return new ActionResponse("SUCCESS", null, null, null, null);
    }

    public static ActionResponse failed(String reason, String description) {
        return new ActionResponse("FAILED", reason, description, null, null);
    }

    public static ActionResponse error(String message, String description) {
        return new ActionResponse("ERROR", null, null, message, description);
    }
}
