package com.onesik.security.web.filter.security.handler;

import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationFailureHandler;
import org.springframework.web.servlet.FlashMap;
import org.springframework.web.servlet.FlashMapManager;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

public abstract class AbstractAuthenticationFailureHandler extends SimpleUrlAuthenticationFailureHandler {

    private final FlashMapManager flashMapManager;

    public static final String ERROR_MESSAGE = "ERR_MSG";

    public AbstractAuthenticationFailureHandler(String targetUrl, FlashMapManager flashMapManager) {
        super(targetUrl);
        this.flashMapManager = flashMapManager;
    }

    protected void setErrorMessage(HttpServletRequest request, HttpServletResponse response, AuthenticationException exception) {
            FlashMap flashMap = new FlashMap();
            flashMap.put(ERROR_MESSAGE, exception.getMessage());
            flashMapManager.saveOutputFlashMap(flashMap, request, response);
    }


}
