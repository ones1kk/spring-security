package com.onesik.security.config;

import com.onesik.security.config.constant.AuthenticationPath;
import com.onesik.security.service.SmsHistoryService;
import com.onesik.security.service.UserService;
import com.onesik.security.web.filter.security.filter.*;
import com.onesik.security.web.filter.security.handler.FirstAuthenticationFailureHandler;
import com.onesik.security.web.filter.security.handler.FirstAuthenticationSuccessHandler;
import com.onesik.security.web.filter.security.handler.SecondAuthenticationFailureHandler;
import com.onesik.security.web.filter.security.handler.SecondAuthenticationSuccessHandler;
import com.onesik.security.web.filter.security.provider.FirstAuthenticationProvider;
import com.onesik.security.web.filter.security.provider.SecondAuthenticationProvider;
import com.onesik.security.web.filter.security.token.FirstAuthenticationToken;
import com.onesik.security.web.filter.security.token.SecondAuthenticationToken;
import com.onesik.security.web.jwt.AbstractJwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.access.intercept.FilterSecurityInterceptor;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;

import java.util.List;
import java.util.stream.Stream;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final UserService userService;

    private final AbstractJwtTokenProvider<Authentication> jwtTokenProvider;

    private final SmsHistoryService smsHistoryService;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers(HttpMethod.GET, staticResources()).permitAll()
                .antMatchers(HttpMethod.GET, "/favicon.ico", "/sm/*/**").permitAll()

                // 1st login
                .antMatchers(AuthenticationPath.FIRST_LOGIN_PAGE.getPath(),
                        AuthenticationPath.FIRST_LOGIN_API.getPath())
                .permitAll()

                // 2nd login
                .antMatchers(AuthenticationPath.SECOND_LOGIN_PAGE.getPath(),
                        AuthenticationPath.SECOND_LOGIN_API.getPath())
                .hasAnyAuthority(FirstAuthenticationToken.AUTHORITY.getAuthority())

                // authenticated pages
                .antMatchers(AuthenticationPath.HOME_PAGE.getPath())
                .hasAnyAuthority(SecondAuthenticationToken.AUTHORITY.getAuthority())

                // logout
                .antMatchers(AuthenticationPath.LOGOUT_API.getPath())
                .hasAnyAuthority(SecondAuthenticationToken.AUTHORITY.getAuthority())

                .antMatchers(allowedResources()).permitAll()

                .anyRequest().denyAll();

        configure(http);
        login(http);
        exceptionHandling(http);

        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        return new ProviderManager(List.of(new FirstAuthenticationProvider(userService), new SecondAuthenticationProvider(smsHistoryService)));
    }

    private void login(HttpSecurity http) throws Exception {
        AbstractFirstAuthenticationFilter firstFilter = new FirstAuthenticateFilter();
        firstFilter.setAuthenticationManager(authenticationManager());
        firstFilter.setAuthenticationSuccessHandler(
                new FirstAuthenticationSuccessHandler(AuthenticationPath.SECOND_LOGIN_PAGE.getPath()
                        , smsHistoryService, jwtTokenProvider, userService));

        firstFilter.setAuthenticationFailureHandler(
                new FirstAuthenticationFailureHandler(AuthenticationPath.FIRST_LOGIN_PAGE.getPath()));

        AbstractAuthenticationProcessingFilter secondFilter = new SecondAuthenticationFilter(jwtTokenProvider, userService);
        secondFilter.setAuthenticationManager(authenticationManager());
        secondFilter.setAuthenticationSuccessHandler(new SecondAuthenticationSuccessHandler(AuthenticationPath.HOME_PAGE.getPath()
                , userService, jwtTokenProvider));
        secondFilter.setAuthenticationFailureHandler(new SecondAuthenticationFailureHandler(AuthenticationPath.FIRST_LOGIN_PAGE.getPath()));

        http.addFilterBefore(firstFilter, FilterSecurityInterceptor.class)
                .addFilterBefore(new SustainingFirstTokenFilter(jwtTokenProvider), FilterSecurityInterceptor.class)
                .addFilterBefore(secondFilter, FilterSecurityInterceptor.class)
                .addFilterBefore(new SustainingSecondTokenFilter(jwtTokenProvider), FilterSecurityInterceptor.class);
    }


    private void configure(HttpSecurity http) throws Exception {
        http.csrf().disable();
        http.cors().disable();
        http.headers().frameOptions().disable();
        http.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);
    }

    private void exceptionHandling(HttpSecurity http) throws Exception {
        // AuthenticationException
        http.exceptionHandling().authenticationEntryPoint(new LoginUrlAuthenticationEntryPoint(AuthenticationPath.FIRST_LOGIN_PAGE.getPath()));

        // AccessDeniedException
        AccessDeniedHandlerImpl handler = new AccessDeniedHandlerImpl();
        handler.setErrorPage(AuthenticationPath.FIRST_LOGIN_PAGE.getPath());
        http.exceptionHandling().accessDeniedHandler(handler);
    }

    private static String[] staticResources() {
        return Stream.of("css", "fonts", "images", "js").map(it -> "/" + it + "/*/**")
                .toArray(String[]::new);
    }

    private static String[] allowedResources() {
        return Stream.of("/apis/*/**").toArray(String[]::new);
    }

}
