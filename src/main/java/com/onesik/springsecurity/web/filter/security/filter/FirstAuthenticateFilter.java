package com.onesik.springsecurity.web.filter.security.filter;

import com.onesik.springsecurity.web.dto.CreateUserDto;
import com.onesik.springsecurity.web.filter.security.token.FirstAuthenticationToken;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@RequiredArgsConstructor
public class FirstAuthenticateFilter extends AbstractFirstAuthenticationFilter {

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        String username = getRequestParam(request, AbstractFirstAuthenticationFilter.USERNAME);
        String birthDate = getRequestParam(request, AbstractFirstAuthenticationFilter.BIRTH_DATE);
        String phoneNumber = getRequestParam(request, AbstractFirstAuthenticationFilter.PHONE_NO);

        CreateUserDto createUser = CreateUserDto.builder()
                .username(username)
                .birthDate(birthDate)
                .phoneNo(phoneNumber)
                .build();

        FirstAuthenticationToken token = new FirstAuthenticationToken(createUser);

        // Call Authentication Provider
        Authentication authenticate = super.getAuthenticationManager().authenticate(token);
        return authenticate;
    }

    private String getRequestParam(HttpServletRequest request, String paramName) {
        return request.getParameter(paramName);
    }

}
