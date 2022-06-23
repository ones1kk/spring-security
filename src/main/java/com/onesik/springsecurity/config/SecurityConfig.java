package com.onesik.springsecurity.config;

import com.onesik.springsecurity.config.constant.AuthenticationPath;
import com.onesik.springsecurity.service.SmsHistoryService;
import com.onesik.springsecurity.service.UserService;
import com.onesik.springsecurity.web.filter.security.filter.AbstractFirstAuthenticationFilter;
import com.onesik.springsecurity.web.filter.security.filter.FirstAuthenticateFilter;
import com.onesik.springsecurity.web.filter.security.filter.config.SecondAuthenticationConfigurer;
import com.onesik.springsecurity.web.filter.security.handler.FirstAuthenticationFailureHandler;
import com.onesik.springsecurity.web.filter.security.handler.FirstAuthenticationSuccessHandler;
import com.onesik.springsecurity.web.filter.security.provider.FirstAuthenticationProvider;
import com.onesik.springsecurity.web.filter.security.provider.SecondAuthenticationProvider;
import com.onesik.springsecurity.web.filter.security.token.FirstAuthenticationToken;
import com.onesik.springsecurity.web.filter.security.token.SecondAuthenticationToken;
import com.onesik.springsecurity.web.jwt.AbstractJwtProvider;
import com.onesik.springsecurity.web.jwt.AuthenticationTypeJwtProvider;
import com.onesik.springsecurity.web.jwt.JwtProvider;
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
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.logout.LogoutFilter;

import java.util.List;
import java.util.stream.Stream;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final UserService userService;

    private final JwtProvider jwtProvider;

    private final SmsHistoryService smsHistoryService;

    @Bean
    public AbstractJwtProvider<Authentication> jwtProvider() {
        return new AuthenticationTypeJwtProvider();
    }

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
        firstFilter.setAuthenticationManager(this.authenticationManager());
        firstFilter.setAuthenticationSuccessHandler(
                new FirstAuthenticationSuccessHandler(AuthenticationPath.SECOND_LOGIN_PAGE.getPath()
                        , smsHistoryService, jwtProvider, userService));

        firstFilter.setAuthenticationFailureHandler(
                new FirstAuthenticationFailureHandler(AuthenticationPath.FIRST_LOGIN_PAGE.getPath()));

        http.apply(new SecondAuthenticationConfigurer<>(jwtProvider, userService))
                .successForwardUrl(AuthenticationPath.HOME_PAGE.getPath())
                .failureForwardUrl(AuthenticationPath.SECOND_LOGIN_PAGE.getPath());

        http.addFilterBefore(firstFilter, LogoutFilter.class);
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
