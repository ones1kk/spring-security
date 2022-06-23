package com.onesik.security.web.filter.security.provider;

import com.onesik.security.domain.SmsHistory;
import com.onesik.security.service.SmsHistoryService;
import com.onesik.security.web.filter.security.token.SecondAuthenticationToken;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

@RequiredArgsConstructor
public class SecondAuthenticationProvider implements AuthenticationProvider {

    private final SmsHistoryService smsHistoryService;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        Long userId = (Long) authentication.getPrincipal();
        String expectedAuthNo = (String) authentication.getCredentials();

        SmsHistory smsHistory = smsHistoryService.findByUserId(userId);
        String authNo = smsHistory.getAuthNo();

        if (!authNo.equals(expectedAuthNo)) throw new BadCredentialsException("Authentication number does not match");

        Authentication token = new SecondAuthenticationToken(userId, authNo);
        token.setAuthenticated(true);

        return token;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return SecondAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
