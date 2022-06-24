package com.onesik.security.web.filter.security.handler;

import com.onesik.security.domain.User;
import com.onesik.security.service.UserService;
import com.onesik.security.web.jwt.AbstractJwtTokenProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

import static com.onesik.security.web.jwt.AbstractJwtTokenProvider.X_AUTH_TOKEN;
import static com.onesik.security.web.util.HttpServletResponseUtil.createCookie;

public class SecondAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {
    private final UserService userService;

    private final AbstractJwtTokenProvider<Authentication> jwtTokenProvider;

    public SecondAuthenticationSuccessHandler(String targetUrl, UserService userService, AbstractJwtTokenProvider<Authentication> jwtTokenProvider) {
        super(targetUrl);
        this.userService = userService;
        this.jwtTokenProvider = jwtTokenProvider;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        User user = (User) authentication.getPrincipal();
        Long userId = user.getId();

        String jwtToken = jwtTokenProvider.createToken(authentication, X_AUTH_TOKEN);
        userService.updateUserJwtToken(jwtToken, userId);

        Cookie cookie = createCookie(X_AUTH_TOKEN, jwtToken);
        response.addCookie(cookie);

        // Doing something ex: save loginHistory...

        super.onAuthenticationSuccess(request, response, authentication);
    }
}
