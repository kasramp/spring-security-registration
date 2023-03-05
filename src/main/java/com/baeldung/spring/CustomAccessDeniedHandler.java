package com.baeldung.spring;

import com.baeldung.persistence.model.User;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static org.springframework.security.core.context.SecurityContextHolder.getContext;

public class CustomAccessDeniedHandler implements AccessDeniedHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(CustomAccessDeniedHandler.class);

    @Override
    public void handle(HttpServletRequest request, HttpServletResponse response, AccessDeniedException accessDeniedException) throws IOException, ServletException {
        String username = getContext().getAuthentication().getName();
        final Object principal = getContext().getAuthentication().getPrincipal();

        if (principal instanceof User) {
            User user = (User) principal;
            username = user.getEmail();
        }
        LOGGER.warn("User {} attempted to access an unauthorized URL: {}", username, request.getServletPath());

        response.sendRedirect(request.getContextPath() + "/accessDenied");
    }
}
