package com.onesik.springsecurity.web.filter.security.provider;

import com.onesik.springsecurity.domain.User;
import com.onesik.springsecurity.service.UserService;
import com.onesik.springsecurity.web.dto.CreateUserDto;
import com.onesik.springsecurity.web.filter.security.token.FirstAuthenticationToken;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

import java.util.UUID;

@RequiredArgsConstructor
public class FirstAuthenticationProvider implements AuthenticationProvider {

    private final UserService service;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
       CreateUserDto userDto =  (CreateUserDto) authentication.getPrincipal();

        String phoneNo = userDto.getPhoneNo();
        User user = service.findByPhoneNo(phoneNo);

        // validate conditions...
        if (user == null) throw new UsernameNotFoundException("존재하는 회원이 없습니다.");


        // create JWT token
        String jwtToken = UUID.randomUUID().toString();
        Authentication token = new FirstAuthenticationToken(user, jwtToken);
        token.setAuthenticated(true);

        // update JWT token

        return token;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return FirstAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
