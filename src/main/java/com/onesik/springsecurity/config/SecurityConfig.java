package com.onesik.springsecurity.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.onesik.springsecurity.config.constant.AuthenticationPath;
import com.onesik.springsecurity.web.filter.security.filter.AbstractAuthenticationFilter;
import com.onesik.springsecurity.web.filter.security.filter.FirstAuthenticateFilter;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.logout.LogoutFilter;

import java.util.stream.Stream;

@Configuration
@RequiredArgsConstructor
public class SecurityConfig {

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeRequests()
                .antMatchers(HttpMethod.GET, staticResources()).permitAll()
                .antMatchers(HttpMethod.GET, "/favicon.ico", "/sm/*/**").permitAll()


//                .antMatchers(allowedResources()).permitAll()

                // first login
                .antMatchers(AuthenticationPath.FIRST_LOGIN_PAGE.getPath(),
                        AuthenticationPath.FIRST_LOGIN_API.getPath())
                .permitAll()

                .anyRequest().denyAll();

        configure(http);
        login(http);

        return http.build();
    }

    private void login(HttpSecurity http) throws Exception {
        AbstractAuthenticationFilter firstFilter = new FirstAuthenticateFilter();


        http.addFilterBefore(firstFilter, LogoutFilter.class);
    }
    
    
    protected void configure(HttpSecurity http) throws Exception {
        http.csrf().disable()
                .cors().disable()
                .headers().frameOptions().disable();
    }

    private static String[] staticResources() {
        return Stream.of("css", "fonts", "images", "js", "security").map(it -> "/" + it + "/*/**")
                .toArray(String[]::new);
    }

    private static String[] allowedResources() {
        return Stream.of("", "").toArray(String[]::new);
    }
}
