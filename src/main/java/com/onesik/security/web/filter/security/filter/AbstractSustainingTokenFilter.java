package com.onesik.security.web.filter.security.filter;

import com.onesik.security.web.jwt.AbstractJwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static com.onesik.security.web.jwt.AbstractJwtTokenProvider.X_AUTH_TOKEN;

@RequiredArgsConstructor
public abstract class AbstractSustainingTokenFilter extends OncePerRequestFilter {

    private final AbstractJwtTokenProvider<Authentication> jwtTokenProvider;

    protected Authentication get(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws IOException, ServletException {
        Cookie[] cookies = request.getCookies();
        if (cookies == null || cookies.length == 0) {
            filterChain.doFilter(request, response);
            return null;
        }

        String jwtToken = jwtTokenProvider.resolveToken(request, X_AUTH_TOKEN);
        return jwtTokenProvider.getAuthentication(jwtToken);
    }


}
