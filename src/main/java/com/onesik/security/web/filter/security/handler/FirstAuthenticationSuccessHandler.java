package com.onesik.security.web.filter.security.handler;

import com.onesik.security.domain.SmsHistory;
import com.onesik.security.domain.User;
import com.onesik.security.service.SmsHistoryService;
import com.onesik.security.service.UserService;
import com.onesik.security.web.jwt.AbstractJwtProvider;
import com.onesik.security.web.jwt.JwtProvider;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class FirstAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final SmsHistoryService smsHistoryService;

    private final UserService userService;

    private final JwtProvider jwtProvider;

    public FirstAuthenticationSuccessHandler(String targetUrl, SmsHistoryService smsHistoryService,
                                             JwtProvider jwtProvider, UserService userService) {
        super(targetUrl);
        this.smsHistoryService = smsHistoryService;
        this.jwtProvider = jwtProvider;
        this.userService = userService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        User user = (User) authentication.getPrincipal();

        SecureRandom secureRandom = new SecureRandom();
        String authNo = IntStream.range(0, 6)
                .mapToObj(i -> secureRandom.nextInt(9))
                .map(String::valueOf)
                .collect(Collectors.joining());

        SmsHistory smsHistory = SmsHistory.builder()
                .authNo(authNo)
                .user(user)
                .localDateTime(LocalDateTime.now())
                .build();

        // send SMS
        smsHistoryService.save(smsHistory);

        String phoneNo = user.getPhoneNo();
        Long userId = user.getId();

        String phoneNoJwtToken = jwtProvider.createToken(phoneNo);
        userService.updateUserJwtToken(phoneNoJwtToken, userId);

        // Add PK, Authentication in Cookie
        // TODO Do not add cookie by PK
        // @Deprecated
        response.addCookie(new Cookie(AbstractJwtProvider.X_AUTH_TOKEN, phoneNoJwtToken));

        // TODO Add Cookie of Authentication
//        String authenticationJwtToken = jwtProvider.createToken(authentication)
//        response.addCookie(new Cookie(AbstractJwtProvider.AUTHENTICATION, authenticationJwtToken));

        super.onAuthenticationSuccess(request, response, authentication);
    }
}
