package com.onesik.springsecurity.web.filter.security.handler;

import com.onesik.springsecurity.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public abstract class AbstractFirstAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    private final String targetUrl;

    private final UserService service;

    protected AbstractFirstAuthenticationFailureHandler(String targetUrl, UserService service) {
        super(targetUrl);
        this.targetUrl = targetUrl;
        this.service = service;
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

        // Save the flash attribute in current session.

        String phoneNo = resolveUserPhoneNo(request);
        if (exception instanceof BadCredentialsException) {
            // create LoginHistory
        }

        // Save login history.


        // Forward or redirect to url.
        if (super.isUseForward()) {
            request.getRequestDispatcher(targetUrl).forward(request, response);
        } else {
            super.getRedirectStrategy().sendRedirect(request, response, this.targetUrl);
        }
    }

    protected abstract String resolveUserPhoneNo(HttpServletRequest request);
}
