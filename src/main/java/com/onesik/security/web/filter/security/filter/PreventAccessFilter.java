package com.onesik.security.web.filter.security.filter;

import com.onesik.security.config.constant.AuthenticationPath;
import com.onesik.security.web.filter.security.token.SecondAuthenticationToken;
import com.onesik.security.web.jwt.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.web.filter.OncePerRequestFilter;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static com.onesik.security.web.jwt.JwtTokenProvider.X_AUTH_TOKEN;

@RequiredArgsConstructor
public class protectAccessFilter extends OncePerRequestFilter {

    private final JwtTokenProvider<Authentication> jwtTokenProvider;

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        Authentication authentication = jwtTokenProvider.resolveAndGet(request, X_AUTH_TOKEN);

        // If user have had 2nd AuthenticationToken
        if (authentication instanceof SecondAuthenticationToken) {
            response.sendRedirect(AuthenticationPath.HOME_PAGE.getPath());
        }

        filterChain.doFilter(request, response);

    }
}
