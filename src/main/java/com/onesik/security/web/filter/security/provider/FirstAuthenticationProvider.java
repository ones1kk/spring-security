package com.onesik.security.web.filter.security.provider;

import com.onesik.security.domain.User;
import com.onesik.security.service.UserService;
import com.onesik.security.web.dto.LoginUserDto;
import com.onesik.security.web.filter.security.token.FirstAuthenticationToken;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UsernameNotFoundException;

@RequiredArgsConstructor
public class FirstAuthenticationProvider implements AuthenticationProvider {

    private final UserService service;

    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        LoginUserDto userDto = (LoginUserDto) authentication.getPrincipal();
        User user = userDto.toEntity();
        String phoneNo = userDto.getPhoneNo();
        User findUser = service.findByPhoneNo(phoneNo);

        // validate conditions...
        if (findUser == null) throw new UsernameNotFoundException("Can not find user.");
        user.clear(findUser.getId());

        if (!user.equals(findUser)) throw new UsernameNotFoundException("Can not find user.");

        Authentication token = new FirstAuthenticationToken(user);
        token.setAuthenticated(true);

        return token;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return FirstAuthenticationToken.class.isAssignableFrom(authentication);
    }
}
