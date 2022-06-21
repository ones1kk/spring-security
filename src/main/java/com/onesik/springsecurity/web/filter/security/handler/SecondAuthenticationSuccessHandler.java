package com.onesik.springsecurity.web.filter.security.handler;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class SecondAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    public SecondAuthenticationSuccessHandler(String targetUrl) {
        super(targetUrl);
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        // Doing something
        super.onAuthenticationSuccess(request, response, authentication);

    }
}
