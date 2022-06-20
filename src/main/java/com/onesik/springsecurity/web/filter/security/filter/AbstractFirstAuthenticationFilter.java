package com.onesik.springsecurity.web.filter.security.filter;

import com.onesik.springsecurity.config.constant.AuthenticationPath;
import org.springframework.http.HttpMethod;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public abstract class AbstractFirstAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    public static final String USERNAME = "username";
    public static final String BIRTH_DATE = "birthDate";
    public static final String PHONE_NO = "phoneNo";

    private static final RequestMatcher DEFAULT_REQUEST_MATCHER = new AntPathRequestMatcher(
            AuthenticationPath.FIRST_LOGIN_API.getPath(), HttpMethod.POST.name());

    protected AbstractFirstAuthenticationFilter() {
        super(DEFAULT_REQUEST_MATCHER);
    }

    protected AbstractFirstAuthenticationFilter(String requestPattern) {
        super(new AntPathRequestMatcher(requestPattern, HttpMethod.POST.name()));
    }

    @Override
    protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
        boolean required = super.requiresAuthentication(request, response);

        Authentication token = SecurityContextHolder.getContext().getAuthentication();
        if (token == null) return required;

        return required;
    }

    @Override
    public abstract Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException;
}
