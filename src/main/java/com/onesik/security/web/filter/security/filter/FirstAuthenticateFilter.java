package com.onesik.security.web.filter.security.filter;

import com.onesik.security.web.dto.LoginUserDto;
import com.onesik.security.web.filter.security.token.FirstAuthenticationToken;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import static com.onesik.security.web.util.HttpServletRequestUtil.getRequestParam;

@RequiredArgsConstructor
public class FirstAuthenticateFilter extends AbstractFirstAuthenticationFilter {

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String username = getRequestParam(request, USERNAME);
        String birthDate = getRequestParam(request, BIRTH_DATE);
        String phoneNumber = getRequestParam(request, PHONE_NO);

        LoginUserDto createUser = LoginUserDto.builder()
                .username(username)
                .birthDate(birthDate)
                .phoneNo(phoneNumber)
                .build();

        FirstAuthenticationToken token = new FirstAuthenticationToken(createUser);

        // Call Authentication Provider
        return super.getAuthenticationManager().authenticate(token);
    }

}
