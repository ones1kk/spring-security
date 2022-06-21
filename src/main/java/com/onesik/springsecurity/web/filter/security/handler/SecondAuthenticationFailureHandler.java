package com.onesik.springsecurity.web.filter.security.handler;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class SecondAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    public SecondAuthenticationFailureHandler(String targetUrl) {
        super(targetUrl);
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {

        // Doing something
        super.onAuthenticationFailure(request, response, exception);

    }

}
