package com.example.iam.pre_update_password_action_service.dto;

import java.util.List;

/**
 * Java view of the JSON that WSO2 IS posts to us.
 * Only the fields we use are declared. Spring Boot disables
 * FAIL_ON_UNKNOWN_PROPERTIES by default, so extra fields in
 * future IS versions are ignored instead of breaking us.
 */
public record ActionRequest(
        String requestId,
        String flowId,
        String actionType,
        Event event) {

    public record Event(
            NamedRef tenant,
            NamedRef userStore,
            User user,
            String initiatorType,   // USER | ADMIN | APPLICATION
            String action) {        // UPDATE | RESET | INVITE | REGISTER
    }

    /** tenant and userStore share the same shape. */
    public record NamedRef(String id, String name) {
    }

    public record User(
            String id,
            List<Claim> claims,
            List<String> groups,
            UpdatingCredential updatingCredential) {
    }

    /** value is Object because multi-valued claims arrive as a JSON array. */
    public record Claim(String uri, Object value) {
    }

    public record UpdatingCredential(
            String type,                    // always PASSWORD today
            String format,                  // PLAIN_TEXT | HASH
            String value,                   // the password itself
            AdditionalData additionalData) {
    }

    public record AdditionalData(String algorithm) {   // e.g. SHA256
    }
}
