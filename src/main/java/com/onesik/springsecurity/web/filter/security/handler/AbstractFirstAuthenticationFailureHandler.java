package com.onesik.springsecurity.web.filter.security.handler;

import com.onesik.springsecurity.domain.User;
import com.onesik.springsecurity.service.UserService;
import org.springframework.http.HttpStatus;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.stereotype.Component;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
@Component
public abstract class AbstractFirstAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    private final String targetUrl;

    protected AbstractFirstAuthenticationFailureHandler(String targetUrl) {
        super(targetUrl);
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

        String phoneNo = resolveUserPhoneNo(request);


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
