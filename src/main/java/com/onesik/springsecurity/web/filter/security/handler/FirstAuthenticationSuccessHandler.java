package com.onesik.springsecurity.web.filter.security.handler;

import com.onesik.springsecurity.domain.User;
import com.onesik.springsecurity.service.UserService;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

public class FirstAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private UserService service;

    public FirstAuthenticationSuccessHandler(String targetUrl, UserService service) {
        super(targetUrl);
        this.service = service;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        super.onAuthenticationSuccess(request, response, authentication);

        User user = (User) authentication.getPrincipal();

        String jwtToken = (String) authentication.getCredentials();
        User findUser = service.findByJwtToken(jwtToken);

        if (!user.equals(findUser)) throw new UsernameNotFoundException("error");

        // create LoginHistory
    }
}
