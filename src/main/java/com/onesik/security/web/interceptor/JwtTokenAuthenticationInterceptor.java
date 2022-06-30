package com.onesik.security.web.interceptor;

import com.onesik.security.domain.User;
import com.onesik.security.service.UserService;
import com.onesik.security.web.exception.NotAuthenticatedUserException;
import com.onesik.security.web.jwt.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.web.servlet.HandlerInterceptor;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

@RequiredArgsConstructor
public class JwtTokenAuthenticationInterceptor implements HandlerInterceptor {

    private final JwtTokenProvider<Authentication> jwtTokenProvider;

    private final UserService userService;

    @Override
    public boolean preHandle(HttpServletRequest request, HttpServletResponse response, Object handler) throws Exception {
        Cookie[] cookies = request.getCookies();
        if (cookies == null || cookies.length == 0) return true;

        String jwtToken = jwtTokenProvider.resolveToken(request, JwtTokenProvider.X_AUTH_TOKEN);

        // Authenticate status of login or not
        if (jwtToken != null) {
            Authentication authentication = jwtTokenProvider.getKey(jwtToken);
            User user = (User) authentication.getPrincipal();
            Long userId = user.getId();

            User findUser = userService.findById(userId);

            if (!findUser.getId().equals(userId)) {
                throw new NotAuthenticatedUserException("Not authenticated user.");
            }

            boolean expired = jwtTokenProvider.validateToken(jwtToken);
            if (!expired) throw new NotAuthenticatedUserException("Invalid user.");

        }

        return true;
    }
}
