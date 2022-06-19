package com.onesik.springsecurity.web.filter.security.handler;

import com.onesik.springsecurity.service.UserService;
import com.onesik.springsecurity.web.filter.security.filter.AbstractAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;

public class FirstAuthenticationFailureHandler extends AbstractFirstAuthenticationFailureHandler {

    protected FirstAuthenticationFailureHandler(String targetUrl, UserService service) {
        super(targetUrl, service);
    }

    @Override
    protected String resolveUserPhoneNo(HttpServletRequest request) {
        String phoneNo = AbstractAuthenticationFilter.PHONE_NO;
        return request.getParameter(phoneNo);
    }
}
