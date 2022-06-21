package com.onesik.springsecurity.config.constant;

import lombok.Getter;
import lombok.RequiredArgsConstructor;

@Getter
@RequiredArgsConstructor
public enum AuthenticationPath {

    FIRST_LOGIN_PAGE("/login/first"),
    FIRST_LOGIN_API("/apis/login/first"),
    SECOND_LOGIN_PAGE("/login/second"),
    SECOND_LOGIN_API("/apis/login/second"),

    HOME_PAGE("/"),

    LOGOUT_API("/apis/logout");

    private final String path;
}
