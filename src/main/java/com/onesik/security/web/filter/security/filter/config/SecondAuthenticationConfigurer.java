package com.onesik.security.web.filter.security.filter.config;

import com.onesik.security.config.constant.AuthenticationPath;
import com.onesik.security.service.UserService;
import com.onesik.security.web.filter.security.filter.AbstractFirstAuthenticationFilter;
import com.onesik.security.web.filter.security.filter.FirstAuthenticateFilter;
import com.onesik.security.web.filter.security.filter.SecondAuthenticationFilter;
import com.onesik.security.web.filter.security.handler.SecondAuthenticationFailureHandler;
import com.onesik.security.web.filter.security.handler.SecondAuthenticationSuccessHandler;
import com.onesik.security.web.jwt.JwtProvider;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.HttpSecurityBuilder;
import org.springframework.security.config.annotation.web.configurers.AbstractAuthenticationFilterConfigurer;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.security.web.util.matcher.RequestMatcher;

public final class SecondAuthenticationConfigurer<H extends HttpSecurityBuilder<H>> extends
        AbstractAuthenticationFilterConfigurer<H, SecondAuthenticationConfigurer<H>, SecondAuthenticationFilter> {

    private final Class<? extends AbstractFirstAuthenticationFilter> filterType;

    private String successForwardUrl = AuthenticationPath.HOME_PAGE.getPath();

    private String failureForwardUrl = AuthenticationPath.SECOND_LOGIN_PAGE.getPath();

    public SecondAuthenticationConfigurer(JwtProvider jwtProvider, UserService userService) {
        super(new SecondAuthenticationFilter(jwtProvider, userService), AuthenticationPath.SECOND_LOGIN_API.getPath());
        this.filterType = FirstAuthenticateFilter.class;
    }

    @Override
    public void init(H http) throws Exception {
        super.init(http);
        initDefaultLoginFilter(http);
    }

    @Override
    public void configure(H http) throws Exception {
        try {
            super.configure(http);
        } catch (IllegalArgumentException e) {
            String message = "Consider using addFilterBefore or addFilterAfter instead.";
            if (!e.getMessage().endsWith(message)) throw e;

            http.addFilterAfter(getAuthenticationFilter(), this.filterType);
        }
    }

    @Override
    protected RequestMatcher createLoginProcessingUrlMatcher(String loginProcessingUrl) {
        return new AntPathRequestMatcher(loginProcessingUrl, HttpMethod.POST.name());
    }

    public SecondAuthenticationConfigurer<H> successForwardUrl(String forwardUrl) {
        this.successForwardUrl = forwardUrl;
        successHandler(new SecondAuthenticationSuccessHandler(this.successForwardUrl));

        return this;
    }

    public SecondAuthenticationConfigurer<H> failureForwardUrl(String forwardUrl) {
        this.failureForwardUrl = forwardUrl;
        failureHandler(new SecondAuthenticationFailureHandler(this.failureForwardUrl));
        return this;
    }

    private void initDefaultLoginFilter(H http) {
        if (this.successForwardUrl == null) successForwardUrl(AuthenticationPath.HOME_PAGE.getPath());
        if (this.failureForwardUrl == null) failureForwardUrl(AuthenticationPath.SECOND_LOGIN_PAGE.getPath());
    }
}
