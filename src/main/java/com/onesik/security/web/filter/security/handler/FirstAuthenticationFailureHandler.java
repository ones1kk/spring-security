package com.onesik.security.web.filter.security.handler;

import com.onesik.security.web.filter.security.filter.AbstractFirstAuthenticationFilter;

import javax.servlet.http.HttpServletRequest;

public class FirstAuthenticationFailureHandler extends AbstractFirstAuthenticationFailureHandler {

    public FirstAuthenticationFailureHandler(String targetUrl) {
        super(targetUrl);
    }

    @Override
    protected String resolveUserPhoneNo(HttpServletRequest request) {
        String phoneNo = AbstractFirstAuthenticationFilter.PHONE_NO;
        return request.getParameter(phoneNo);
    }
}
