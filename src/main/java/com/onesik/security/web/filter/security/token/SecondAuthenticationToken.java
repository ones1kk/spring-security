package com.onesik.security.web.filter.security.token;

import com.onesik.security.web.filter.security.token.authority.CustomGrantedAuthority;
import lombok.Setter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Collections;

public class SecondAuthenticationToken extends AbstractAuthenticationToken {

    public static final CustomGrantedAuthority AUTHORITY = new CustomGrantedAuthority("SECOND");

    private final Collection<CustomGrantedAuthority> authorities;
    @Setter
    private Object principal;

    private String credentials;

    /**
     * Default Constructor for parsing Authentication to json
     * {@link com.fasterxml.jackson.datatype.jsr310.JavaTimeModule}
     */
    protected SecondAuthenticationToken() {
        super(Collections.singletonList(AUTHORITY));
        this.authorities = Collections.singletonList(AUTHORITY);
    }

    public SecondAuthenticationToken(Object principal, String credentials) {
        super(Collections.singletonList(AUTHORITY));
        this.principal = principal;
        this.credentials = credentials;
        this.authorities = Collections.singletonList(AUTHORITY);

        validate(principal, credentials);
    }

    private void validate(Object principal, String credentials) {
        if (principal == null || credentials == null) throw new NullPointerException();
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
    public String getName() {
        return this.getClass().getSimpleName();
    }

    @Override
    @SuppressWarnings("unchecked")
    public Collection<GrantedAuthority> getAuthorities() {
        return (Collection<GrantedAuthority>) (Object) this.authorities;
    }

}
