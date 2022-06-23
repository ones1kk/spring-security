package com.onesik.security.web.filter.security.filter;

import com.onesik.security.config.constant.AuthenticationPath;
import com.onesik.security.domain.User;
import com.onesik.security.service.UserService;
import com.onesik.security.web.filter.security.token.FirstAuthenticationToken;
import com.onesik.security.web.filter.security.token.SecondAuthenticationToken;
import com.onesik.security.web.jwt.JwtProvider;
import org.springframework.http.HttpMethod;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class SecondAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private final JwtProvider jwtProvider;

    private final UserService userService;

    public static final String AUTHENTICATION_NUMBER = "authNo";

    private static final RequestMatcher DEFAULT_REQUEST_MATCHER = new AntPathRequestMatcher(
            AuthenticationPath.SECOND_LOGIN_API.getPath(), HttpMethod.POST.name());

    public SecondAuthenticationFilter(JwtProvider jwtProvider, UserService userService) {
        super(DEFAULT_REQUEST_MATCHER);
        this.jwtProvider = jwtProvider;
        this.userService = userService;
    }

    public SecondAuthenticationFilter(String requestPattern, JwtProvider jwtProvider, UserService userService) {
        super(new AntPathRequestMatcher(requestPattern, HttpMethod.POST.name()).getPattern());
        this.jwtProvider = jwtProvider;
        this.userService = userService;
    }

    protected boolean requiresAuthentication(HttpServletRequest request, HttpServletResponse response) {
        boolean required = super.requiresAuthentication(request, response);

        Authentication token = SecurityContextHolder.getContext().getAuthentication();
        if (token == null) return required;

        for (GrantedAuthority auth : token.getAuthorities()) {
            if (auth.getAuthority().equals(SecondAuthenticationToken.AUTHORITY.getAuthority())) return false;
        }

        // 2nd authentication is required when 1st authentication is succeeded.
        required &= (token instanceof FirstAuthenticationToken);
        required &= (token.getPrincipal() instanceof User);

        return required;
    }

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException, IOException, ServletException {
        String phoneNo = jwtProvider.resolveToken(request);

        User user = userService.findByPhoneNo(phoneNo);
        Long userId = user.getId();

        String expectedAuthNo = getParamFromRequest(request, AUTHENTICATION_NUMBER);

        Authentication token = new SecondAuthenticationToken(userId, expectedAuthNo);

        return super.getAuthenticationManager().authenticate(token);
    }

    private String getParamFromRequest(HttpServletRequest request, String name) {
        return request.getParameter(name);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        super.getFailureHandler().onAuthenticationFailure(request, response, failed);
    }
}
