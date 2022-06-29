package com.onesik.security.web.controller;

import com.onesik.security.domain.User;
import com.onesik.security.service.UserService;
import com.onesik.security.web.jwt.JwtTokenProvider;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import javax.servlet.http.HttpServletRequest;

import static com.onesik.security.web.jwt.JwtTokenProvider.X_AUTH_TOKEN;

@Controller
@RequiredArgsConstructor
public class ViewController {

    private final UserService userService;
    private final JwtTokenProvider<Authentication> jwtTokenProvider;

    private final JwtTokenProvider<String> exception;

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
    String getFirstLoginPage(HttpServletRequest request, Model model) {
        return "login/first";
    }

    @GetMapping("/login/second")
    String getSecondLoginPage() {
        return "login/second";
    }
}
