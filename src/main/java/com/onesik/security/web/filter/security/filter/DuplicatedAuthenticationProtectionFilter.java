package com.onesik.security.web.filter.security.filter;

import com.onesik.security.config.constant.AuthenticationPath;
import com.onesik.security.web.filter.security.token.SecondAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

public class DuplicatedAuthenticationProtectionFilter extends AbstractHttpFilter {


    private final List<String> targetPaths;

    public DuplicatedAuthenticationProtectionFilter(String... targetUris) {
        this.targetPaths = Collections.unmodifiableList(Arrays.asList(targetUris));
    }

    @Override
    protected void doFilter(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        String contextPath = request.getContextPath();
        if (!required(request, contextPath)) {
            filterChain.doFilter(request, response);
            return;
        }

        response.sendRedirect(contextPath + AuthenticationPath.HOME_PAGE.getPath());
    }

    private boolean required(HttpServletRequest request, String contextPath) {
        Authentication token = SecurityContextHolder.getContext().getAuthentication();
        String requestPath = request.getRequestURI().replaceFirst(contextPath, "");

        return token != null && token.isAuthenticated() && token instanceof SecondAuthenticationToken
                && this.targetPaths.contains(requestPath);
    }
}
