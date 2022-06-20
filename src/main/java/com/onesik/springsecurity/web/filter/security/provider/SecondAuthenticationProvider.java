package com.onesik.springsecurity.web.filter.security.provider;

import com.onesik.springsecurity.web.filter.security.token.SecondAuthenticationToken;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

@RequiredArgsConstructor
public class SecondAuthenticationProvider implements AuthenticationProvider {

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        return null;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return SecondAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
