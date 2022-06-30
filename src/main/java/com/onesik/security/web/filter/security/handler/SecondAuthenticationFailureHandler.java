package com.onesik.security.web.filter.security.handler;

import org.springframework.security.core.AuthenticationException;
import org.springframework.web.servlet.FlashMapManager;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class SecondAuthenticationFailureHandler extends AbstractAuthenticationFailureHandler {


    public SecondAuthenticationFailureHandler(String targetUrl, FlashMapManager flashMapManager) {
        super(targetUrl, flashMapManager);
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {

        setErrorMessage(request, response, exception);

        // Doing something
        super.onAuthenticationFailure(request, response, exception);

    }

}
