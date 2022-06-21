package com.onesik.springsecurity.web.filter.security.handler;

import com.onesik.springsecurity.domain.SmsHistory;
import com.onesik.springsecurity.domain.User;
import com.onesik.springsecurity.service.SmsHistoryService;
import com.onesik.springsecurity.service.UserService;
import com.onesik.springsecurity.web.jwt.JwtProvider;
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

        String jwtToken = jwtProvider.createToken(phoneNo);
        userService.updateUserJwtToken(jwtToken, userId);

        // 토큰 정보를 Response에 담는다
        response.addCookie(new Cookie("X-AUTH-TOKEN", jwtToken));

        super.onAuthenticationSuccess(request, response, authentication);
    }
}
