package com.onesik.security.config;

import com.onesik.security.service.UserService;
import com.onesik.security.web.interceptor.JwtTokenAuthenticationInterceptor;
import com.onesik.security.web.jwt.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.core.Authentication;
import org.springframework.web.servlet.config.annotation.InterceptorRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

import java.util.List;
import java.util.stream.Collectors;
import java.util.stream.Stream;

@Configuration
@RequiredArgsConstructor
public class WebMvcConfig implements WebMvcConfigurer {

    private final JwtTokenProvider<Authentication> jwtTokenProvider;

    private final UserService userService;

    @Override
    public void addInterceptors(InterceptorRegistry registry) {
        registry.addInterceptor(new JwtTokenAuthenticationInterceptor(jwtTokenProvider, userService))
                .addPathPatterns("/**")
                .excludePathPatterns(staticResources());
    }

    private static List<String> staticResources() {
        return Stream.of("css", "fonts", "images", "js").map(it -> "/" + it + "/*/**")
                .collect(Collectors.toList());
    }
}
