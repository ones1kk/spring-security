package com.onesik.springsecurity.config;

import com.onesik.springsecurity.config.constant.AuthenticationPath;
import com.onesik.springsecurity.service.SmsHistoryService;
import com.onesik.springsecurity.service.UserService;
import com.onesik.springsecurity.web.filter.security.filter.AbstractFirstAuthenticationFilter;
import com.onesik.springsecurity.web.filter.security.filter.FirstAuthenticateFilter;
import com.onesik.springsecurity.web.filter.security.handler.FirstAuthenticationFailureHandler;
import com.onesik.springsecurity.web.filter.security.handler.FirstAuthenticationSuccessHandler;
import com.onesik.springsecurity.web.filter.security.provider.FirstAuthenticationProvider;
import com.onesik.springsecurity.web.jwt.JwtProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.ProviderManager;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.AccessDeniedHandlerImpl;
import org.springframework.security.web.authentication.LoginUrlAuthenticationEntryPoint;
import org.springframework.security.web.authentication.logout.LogoutFilter;

import java.util.List;
import java.util.stream.Stream;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    private final UserService service;

    private final JwtProvider jwtProvider;

    private final SmsHistoryService smsHistoryService;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers(HttpMethod.GET, staticResources()).permitAll()
                .antMatchers(HttpMethod.GET, "/favicon.ico", "/sm/*/**").permitAll()

                // first login
                .antMatchers(AuthenticationPath.FIRST_LOGIN_PAGE.getPath(),
                        AuthenticationPath.FIRST_LOGIN_API.getPath())
                .permitAll()

                // second login

                .antMatchers(allowedResources()).permitAll()

                .anyRequest().denyAll();

        configure(http);
        login(http);
        exceptionHandling(http);

        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager() {
        ProviderManager manager = new ProviderManager(List.of(new FirstAuthenticationProvider(service)));
        List<AuthenticationProvider> providers = manager.getProviders();
        providers.forEach(System.out::println);
        return manager;
    }


    private void login(HttpSecurity http) throws Exception {
        AbstractFirstAuthenticationFilter firstFilter = new FirstAuthenticateFilter();
        firstFilter.setAuthenticationManager(this.authenticationManager());
        firstFilter.setAuthenticationSuccessHandler(
                new FirstAuthenticationSuccessHandler(AuthenticationPath.SECOND_LOGIN_PAGE.getPath(), smsHistoryService));
        firstFilter.setAuthenticationFailureHandler(
                new FirstAuthenticationFailureHandler(AuthenticationPath.FIRST_LOGIN_PAGE.getPath()));

        http.addFilterBefore(firstFilter, LogoutFilter.class);
    }


    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .cors().disable()
                .headers().frameOptions().disable();
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
        return Stream.of("css", "fonts", "images", "js", "security").map(it -> "/" + it + "/*/**")
                .toArray(String[]::new);
    }

    private static String[] allowedResources() {
        return Stream.of("/**").toArray(String[]::new);
    }

}
