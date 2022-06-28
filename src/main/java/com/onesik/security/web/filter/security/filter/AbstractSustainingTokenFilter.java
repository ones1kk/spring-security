package com.onesik.security.web.filter.security.filter;

import com.onesik.security.web.jwt.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.io.IOException;

import static com.onesik.security.web.jwt.JwtTokenProvider.X_AUTH_TOKEN;

@RequiredArgsConstructor
public abstract class AbstractSustainingTokenFilter extends OncePerRequestFilter {

    private final JwtTokenProvider<Authentication> jwtTokenProvider;

    protected Authentication get(HttpServletRequest request) throws IOException, ServletException {
        Cookie[] cookies = request.getCookies();
        if (cookies == null || cookies.length == 0) {
            return null;
        }

        String jwtToken = jwtTokenProvider.resolveToken(request, X_AUTH_TOKEN);
        if (jwtToken == null) return null;
        return jwtTokenProvider.getKey(jwtToken);
    }


}
