package com.onesik.security.web.util;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletResponse;

public class HttpServletResponseUtil {

    public static Cookie createCookie(String key, String value) {
        Cookie cookie = new Cookie(key, value);
        cookie.setPath("/");
        cookie.setMaxAge((60 * 60 * 24) * 3);

        return cookie;
    }

    public static void expireCookie(HttpServletResponse response, String... cookieName) {
        for (String name : cookieName) {
            Cookie expiredTokenCookie = new Cookie(name, "");
            expiredTokenCookie.setMaxAge(0);
            expiredTokenCookie.setPath("/");

            response.addCookie(expiredTokenCookie);
        }
    }
}
