package com.onesik.security.web.filter.security.token;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;

import java.util.Collections;

public class FirstAuthenticationToken extends AbstractAuthenticationToken {

    public static final GrantedAuthority AUTHORITY = new SimpleGrantedAuthority("FIRST");

    private final Object principal;

    public FirstAuthenticationToken(Object principal) {
        super(Collections.singletonList(AUTHORITY));
        this.principal = principal;

        validate(principal);
    }

    public void validate(Object principal) {
        if (principal == null) throw new NullPointerException("User can not be null");
    }

    @Override
    public Object getCredentials() {
        return null;
    }

    @Override
    public Object getPrincipal() {
        return principal;
    }

    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
    }

    @Override
    public String getName() {
        return this.getClass().getSimpleName();
    }

}
