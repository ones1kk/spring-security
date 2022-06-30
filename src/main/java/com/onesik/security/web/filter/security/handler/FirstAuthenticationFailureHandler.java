package com.onesik.security.web.filter.security.handler;

import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.web.servlet.FlashMapManager;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class FirstAuthenticationFailureHandler extends AbstractAuthenticationFailureHandler {

    private final String targetUrl;

    public FirstAuthenticationFailureHandler(String targetUrl, FlashMapManager flashMapManager) {
        super(targetUrl, flashMapManager);
        this.targetUrl = targetUrl;
    }

    @Override
    public void onAuthenticationFailure(HttpServletRequest request, HttpServletResponse response,
                                        AuthenticationException exception) throws IOException, ServletException {
        if (this.targetUrl == null) {
            if (super.logger.isTraceEnabled()) {
                super.logger.trace("Sending 401 Unauthorized error since no failure URL is set");
            } else {
                super.logger.debug("Sending 401 Unauthorized error");
            }

            response.sendError(HttpStatus.UNAUTHORIZED.value(), HttpStatus.UNAUTHORIZED.getReasonPhrase());
            return;
        }

        saveException(request, exception);

        setErrorMessage(request, response, exception);

        // Doing something else...

        // Forward or redirect to url.
        if (super.isUseForward()) {
            request.getRequestDispatcher(targetUrl).forward(request, response);
        } else {
            super.getRedirectStrategy().sendRedirect(request, response, this.targetUrl);
        }
    }
}
