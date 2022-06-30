package com.onesik.security.web.controller;

import com.onesik.security.domain.User;
import com.onesik.security.service.UserService;
import com.onesik.security.web.jwt.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;

import javax.servlet.http.HttpServletRequest;

import static com.onesik.security.web.filter.security.handler.FirstAuthenticationFailureHandler.ERROR_MESSAGE;
import static com.onesik.security.web.jwt.JwtTokenProvider.X_AUTH_TOKEN;

@Controller
@RequiredArgsConstructor
public class ViewController {

    private final UserService userService;
    private final JwtTokenProvider<Authentication> jwtTokenProvider;

    @ModelAttribute
    public void getErrorMessage(Model model, @ModelAttribute(ERROR_MESSAGE) String errorMessage) {
        if (StringUtils.hasText(errorMessage)) {
            model.addAttribute("errorMessage", errorMessage);
        }
    }

    @GetMapping("/home")
    String getHomePage(HttpServletRequest request, Model model) {
        Authentication authentication = jwtTokenProvider.resolveAndGet(request, X_AUTH_TOKEN);

        User user = (User) authentication.getPrincipal();
        Long userId = user.getId();

        User findUser = userService.findById(userId);

        model.addAttribute("user", findUser);

        return "home";
    }

    @GetMapping("/login/first")
    String getFirstLoginPage() {
        return "login/first";
    }

    @GetMapping("/login/second")
    String getSecondLoginPage() {
        return "login/second";
    }
}
