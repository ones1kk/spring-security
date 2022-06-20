package com.onesik.springsecurity.web.filter.security.handler;

import com.onesik.springsecurity.domain.SmsHistory;
import com.onesik.springsecurity.domain.User;
import com.onesik.springsecurity.service.SmsHistoryService;
import com.onesik.springsecurity.service.UserService;
import com.onesik.springsecurity.web.jwt.JwtProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.security.web.authentication.SimpleUrlAuthenticationSuccessHandler;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.security.SecureRandom;
import java.time.LocalDateTime;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

@RequiredArgsConstructor
public class FirstAuthenticationSuccessHandler extends SimpleUrlAuthenticationSuccessHandler {

    private final SmsHistoryService smsHistoryService;

    public FirstAuthenticationSuccessHandler(String targetUrl, SmsHistoryService smsHistoryService) {
        super(targetUrl);
        this.smsHistoryService = smsHistoryService;
    }

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        super.onAuthenticationSuccess(request, response, authentication);

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

    }
}
