package com.example.iam.pre_update_password_action_service.security;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

@Component
public class BasicAuthFilter extends OncePerRequestFilter {

    private static final Logger LOG = LoggerFactory.getLogger(BasicAuthFilter.class);

    private final String expectedHeader;
    private final boolean enabled;

    public BasicAuthFilter(@Value("${action.auth.username:}") String username,
                           @Value("${action.auth.password:}") String password) {
        this.enabled = !username.isBlank() && !password.isBlank();
        if (enabled) {
            String encoded = Base64.getEncoder().encodeToString(
                    (username + ":" + password).getBytes(StandardCharsets.UTF_8));
            this.expectedHeader = "Basic " + encoded;
        } else {
            this.expectedHeader = null;
            LOG.warn("action.auth.* not set: the action endpoint is NOT authenticated.");
        }
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return !enabled || !request.getRequestURI().startsWith("/actions/validate-password");
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {

        String provided = request.getHeader(HttpHeaders.AUTHORIZATION);

        if (provided == null || !MessageDigest.isEqual(
                provided.getBytes(StandardCharsets.UTF_8),
                expectedHeader.getBytes(StandardCharsets.UTF_8))) {

            LOG.warn("Unauthenticated call from {}", request.getRemoteAddr());
            response.setStatus(HttpServletResponse.SC_UNAUTHORIZED);
            response.setContentType(MediaType.APPLICATION_JSON_VALUE);
            response.getWriter().write(
                    "{\"actionStatus\":\"ERROR\",\"errorMessage\":\"unauthorized\","
                            + "\"errorDescription\":\"Invalid or missing credentials.\"}");
            return;
        }

        chain.doFilter(request, response);
    }
}
