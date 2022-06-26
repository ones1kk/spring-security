package com.onesik.security.web.interceptor;

import com.onesik.security.web.jwt.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static com.onesik.security.web.jwt.JwtTokenProvider.X_AUTH_TOKEN;

@RequiredArgsConstructor
public class JwtTokenAuthenticationInterceptor implements HandlerInterceptor {

    private final JwtTokenProvider<Authentication> jwtTokenProvider;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        Cookie[] cookies = request.getCookies();
        if (cookies == null || cookies.length == 0) {
            return true;
        } else {
            String jwtToken = jwtTokenProvider.resolveToken(request, X_AUTH_TOKEN);

            return jwtTokenProvider.validateToken(jwtToken);
        }
    }
}
