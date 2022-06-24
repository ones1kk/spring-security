package com.onesik.security.web.filter.security.filter;

import com.onesik.security.config.constant.AuthenticationPath;
import com.onesik.security.domain.User;
import com.onesik.security.service.UserService;
import com.onesik.security.web.exception.NotAuthenticatedUserException;
import com.onesik.security.web.filter.security.token.FirstAuthenticationToken;
import com.onesik.security.web.filter.security.token.SecondAuthenticationToken;
import com.onesik.security.web.jwt.AbstractJwtTokenProvider;
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

import static com.onesik.security.web.jwt.AbstractJwtTokenProvider.X_AUTH_TOKEN;
import static com.onesik.security.web.util.HttpServletResponseUtil.expireCookie;

public class SecondAuthenticationFilter extends AbstractAuthenticationProcessingFilter {

    private final AbstractJwtTokenProvider<Authentication> jwtTokenProvider;

    private final UserService userService;

    public static final String AUTHENTICATION_NUMBER = "authNo";

    private static final RequestMatcher DEFAULT_REQUEST_MATCHER = new AntPathRequestMatcher(
            AuthenticationPath.SECOND_LOGIN_API.getPath(), HttpMethod.POST.name());

    public SecondAuthenticationFilter(AbstractJwtTokenProvider<Authentication> jwtTokenProvider, UserService userService) {
        super(DEFAULT_REQUEST_MATCHER);
        this.jwtTokenProvider = jwtTokenProvider;
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
        String jwtToken = jwtTokenProvider.resolveToken(request, X_AUTH_TOKEN);
        Authentication authentication = jwtTokenProvider.getAuthentication(jwtToken);
        User user = (User) authentication.getPrincipal();
        String phoneNo = user.getPhoneNo();

        User findUser = userService.findByPhoneNo(phoneNo);

        if (!user.equals(findUser)) throw new NotAuthenticatedUserException();

        String expectedAuthNo = getParamFromRequest(request, AUTHENTICATION_NUMBER);

        Authentication token = new SecondAuthenticationToken(findUser, expectedAuthNo);

        expireCookie(response, X_AUTH_TOKEN);

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
