package com.onesik.security.web.filter.security.handler;

import com.onesik.security.domain.SmsHistory;
import com.onesik.security.domain.User;
import com.onesik.security.service.SmsHistoryService;
import com.onesik.security.service.UserService;
import com.onesik.security.web.jwt.AbstractJwtTokenProvider;
import com.onesik.security.web.util.HttpServletResponseUtil;
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

import static com.onesik.security.web.jwt.AbstractJwtTokenProvider.X_AUTH_TOKEN;
import static com.onesik.security.web.util.HttpServletResponseUtil.*;

public class FirstAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final SmsHistoryService smsHistoryService;

    private final UserService userService;

    private final AbstractJwtTokenProvider<Authentication> jwtTokenProvider;

    public FirstAuthenticationSuccessHandler(String targetUrl, SmsHistoryService smsHistoryService,
                                             AbstractJwtTokenProvider<Authentication> jwtTokenProvider, UserService userService) {
        super(targetUrl);
        this.smsHistoryService = smsHistoryService;
        this.jwtTokenProvider = jwtTokenProvider;
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
                .createDatetime(LocalDateTime.now())
                .build();

        // send SMS
        smsHistoryService.save(smsHistory);

        String phoneNo = user.getPhoneNo();
        Long userId = user.getId();

        String jwtToken = jwtTokenProvider.createToken(authentication, X_AUTH_TOKEN);
        userService.updateUserJwtToken(jwtToken, userId);

        Cookie cookie = createCookie(X_AUTH_TOKEN, jwtToken);
        response.addCookie(cookie);

        super.onAuthenticationSuccess(request, response, authentication);
    }
}
