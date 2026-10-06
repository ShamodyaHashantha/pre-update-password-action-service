package com.example.iam.pre_update_password_action_service.web;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import com.example.iam.pre_update_password_action_service.dto.ActionRequest;
import com.example.iam.pre_update_password_action_service.dto.ActionResponse;
import com.example.iam.pre_update_password_action_service.service.PasswordPolicyValidator;

/**
 * The endpoint IS calls while a password update is in flight.
 * The end user is waiting on this response, so keep it fast.
 */
@RestController
@RequestMapping("/actions")
public class PasswordActionController {

    private static final Logger LOG = LoggerFactory.getLogger(PasswordActionController.class);

    private final PasswordPolicyValidator validator;

    public PasswordActionController(PasswordPolicyValidator validator) {
        this.validator = validator;
    }

    @PostMapping(value = "/validate-password",
            consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<ActionResponse> validatePassword(@RequestBody ActionRequest request) {

        LOG.info("Action invoked [actionType={}, requestId={}, flowId={}]",
                request.actionType(), request.requestId(), request.flowId());

        try {
            ActionResponse response = validator.validate(request);

            // SUCCESS and FAILED are both HTTP 200. Only ERROR uses 4xx/5xx.
            HttpStatus status = "ERROR".equals(response.actionStatus())
                    ? HttpStatus.INTERNAL_SERVER_ERROR
                    : HttpStatus.OK;

            return ResponseEntity.status(status).body(response);

        } catch (RuntimeException e) {
            // Never let a stack trace escape as an unstructured 500.
            LOG.error("Unexpected failure [requestId={}]", request.requestId(), e);
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body(ActionResponse.error("server_error",
                            "Error while evaluating the password policy."));
        }
    }

    /** Handy for checking that ngrok points at a live service. */
    @GetMapping("/health")
    public ResponseEntity<String> health() {
        return ResponseEntity.ok("UP");
    }
}
