package com.onesik.security.web.filter.security.token;

import com.onesik.security.web.filter.security.token.authority.CustomGrantedAuthority;
import lombok.Setter;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;
import java.util.Collections;

public class FirstAuthenticationToken extends AbstractAuthenticationToken {

    public static final CustomGrantedAuthority AUTHORITY = new CustomGrantedAuthority("FIRST");

    private final Collection<CustomGrantedAuthority> authorities;

    @Setter
    private Object principal;

    /**
     * Default Constructor for parsing Authentication to json
     * {@link com.fasterxml.jackson.datatype.jsr310.JavaTimeModule}
     */
    protected FirstAuthenticationToken() {
        super(Collections.singletonList(AUTHORITY));
        this.authorities = Collections.singletonList(AUTHORITY);
    }

    public FirstAuthenticationToken(Object principal) {
        super(Collections.singletonList(AUTHORITY));
        this.authorities = Collections.singletonList(AUTHORITY);
        this.principal = principal;
        validate(principal);
    }

    private void validate(Object principal) {
        if (principal == null) throw new NullPointerException("User can not be null");
    }

    @Override
    public void eraseCredentials() {
        super.eraseCredentials();
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
    public String getName() {
        return this.getClass().getSimpleName();
    }

    @Override
    @SuppressWarnings("unchecked")
    public Collection<GrantedAuthority> getAuthorities() {
        return (Collection<GrantedAuthority>) (Object) this.authorities;
    }

}
