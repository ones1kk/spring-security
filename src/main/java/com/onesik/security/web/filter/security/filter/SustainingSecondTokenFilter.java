package com.onesik.security.web.filter.security.filter;

import com.onesik.security.web.filter.security.token.FirstAuthenticationToken;
import com.onesik.security.web.jwt.AbstractJwtTokenProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class SustainingSecondTokenFilter extends AbstractSustainingTokenFilter {

    public SustainingSecondTokenFilter(AbstractJwtTokenProvider<Authentication> jwtTokenProvider) {
        super(jwtTokenProvider);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        Authentication authentication = get(request, response, filterChain);
        if (authentication == null) return;

        if (authentication instanceof FirstAuthenticationToken) {
            filterChain.doFilter(request, response);
            return;
        }

        SecurityContextHolder.getContext().setAuthentication(authentication);
        authentication.setAuthenticated(true);

        filterChain.doFilter(request, response);
    }


}