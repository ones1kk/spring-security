package com.onesik.security.web.filter.security.handler;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.onesik.security.web.jwt.JwtTokenProvider;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static com.onesik.security.web.jwt.JwtTokenProvider.ERROR_MESSAGE;
import static com.onesik.security.web.util.HttpServletResponseUtil.createCookie;

public class FirstAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    private final String targetUrl;

    private final JwtTokenProvider<String> jwtTokenProvider;

    public FirstAuthenticationFailureHandler(String targetUrl, ObjectMapper objectMapper) {
        super(targetUrl);
        this.targetUrl = targetUrl;
        this.jwtTokenProvider = new JwtTokenProvider<>(objectMapper);
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

        // TODO Refactor(had errors)
        if (exception instanceof UsernameNotFoundException) {
            String message = "cannotfinduser";
            String jwtToken = jwtTokenProvider.createToken(message, ERROR_MESSAGE);
            createCookie(ERROR_MESSAGE, jwtToken);
        }

        // Doing something else...

        // Forward or redirect to url.
        if (super.isUseForward()) {
            request.getRequestDispatcher(targetUrl).forward(request, response);
        } else {
            super.getRedirectStrategy().sendRedirect(request, response, this.targetUrl);
        }
    }
}
