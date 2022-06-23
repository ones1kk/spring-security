package com.onesik.security.web.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class ViewController {

    @GetMapping("/home")
    String getHomePage() {
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
