package com.onesik.springsecurity.web.filter.security.token;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collection;
import java.util.Collections;

public class SecondAuthenticationToken extends AbstractAuthenticationToken {

    public static final GrantedAuthority AUTHORITY = new SimpleGrantedAuthority("SECOND");

    private final Object principal;

    private final String credentials;

    public SecondAuthenticationToken(Object principal, String credentials) {
        super(Collections.singletonList(AUTHORITY));
        this.principal = principal;
        this.credentials = credentials;

        validate(principal, credentials);
    }

    private void validate(Object principal, String credentials) {
        if(principal == null || credentials == null) throw new NullPointerException();
    }

    @Override
    public Object getCredentials() {
        return credentials;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }
}
