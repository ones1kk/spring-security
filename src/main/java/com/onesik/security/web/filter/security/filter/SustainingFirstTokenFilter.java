package com.onesik.security.web.filter.security.filter;

import com.onesik.security.web.filter.security.token.SecondAuthenticationToken;
import com.onesik.security.web.jwt.JwtTokenProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;


public class SustainingFirstTokenFilter extends AbstractSustainingTokenFilter {

    public SustainingFirstTokenFilter(JwtTokenProvider<Authentication> jwtTokenProvider) {
        super(jwtTokenProvider);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        Authentication authentication = get(request, response, filterChain);
        if (authentication == null) {
            filterChain.doFilter(request, response);
            return;
        }

        if (authentication instanceof SecondAuthenticationToken) {
            filterChain.doFilter(request, response);
            return;
        }

        SecurityContextHolder.getContext().setAuthentication(authentication);
        authentication.setAuthenticated(true);

        filterChain.doFilter(request, response);

    }
}

