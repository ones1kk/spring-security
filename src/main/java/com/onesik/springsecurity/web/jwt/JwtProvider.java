package com.onesik.springsecurity.web.jwt;

import io.jsonwebtoken.*;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import javax.servlet.ServletRequest;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

@Component
@RequiredArgsConstructor
public class JwtProvider {

    private final String secretKey = "c88d74ba-1554-48a4-b549-b926f5d77c9e";

    private final static String X_AUTH_TOKEN = "x-auth-token";

    // 3일
    private static final long expiredTime = ((3 * 60 * 1000L) * 24) * 60;

    public String createAccessToken(String phoneNo) {
        Map<String, Object> headers = new HashMap<>();
        headers.put("type", "token");

        Map<String, Object> payloads = new HashMap<>();
        payloads.put("phoneNo", phoneNo);

        Date expiration = new Date();
        expiration.setTime(expiration.getTime() + expiredTime);

        return Jwts
                .builder()
                .setHeader(headers)
                .setClaims(payloads)
                .setSubject("user")
                .setExpiration(expiration)
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .compact();
    }

    public String getPhoneNo(String token) {
        return (String) Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody().get("phoneNo");
    }

    public String resolveToken(HttpServletRequest request) {
        Optional<Cookie> cookie = Stream.of(request.getCookies())
                .filter(cookies -> cookies.getName().equals(X_AUTH_TOKEN))
                .findFirst();

        if (cookie.isEmpty()) return null;

        return cookie.get().getValue();
    }

    public boolean validateJwtToken(ServletRequest request, String authToken) {
        try {
            Jwts.parser().setSigningKey(secretKey).parseClaimsJws(authToken);
            return true;
        } catch (MalformedJwtException e) {
            request.setAttribute("exception", "MalformedJwtException");
        } catch (ExpiredJwtException e) {
            request.setAttribute("exception", "ExpiredJwtException");
        } catch (UnsupportedJwtException e) {
            request.setAttribute("exception", "UnsupportedJwtException");
        } catch (IllegalArgumentException e) {
            request.setAttribute("exception", "IllegalArgumentException");
        }
        return false;
    }

}
