package com.onesik.springsecurity.web.filter.security.token;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collections;

public class FirstAuthenticationToken extends AbstractAuthenticationToken {

    public static final GrantedAuthority AUTHORITY = new SimpleGrantedAuthority("FIRST");

    private final Object principal;

    private final String credentials;

    public FirstAuthenticationToken(Object principal, String credentials) {
        super(Collections.singletonList(AUTHORITY));
        this.principal = principal;
        this.credentials = credentials;
        validate(principal, credentials);
    }

    public void validate(Object principal, String credentials) {
        if (principal == null) throw new NullPointerException("User can not be null");
    }

    @Override
    public Object getCredentials() {
        return credentials;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }

    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
    }
}
