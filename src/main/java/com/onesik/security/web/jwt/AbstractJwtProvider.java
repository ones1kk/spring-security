package com.onesik.security.web.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;

import javax.annotation.PostConstruct;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.util.*;


public abstract class AbstractJwtProvider<T> {

    private String secretKey = "c88d74ba-1554-48a4-b549-b926f5d77c9e";

    public final static String X_AUTH_TOKEN = "X_AUTH_TOKEN";

    // 3 Days
    protected static final long expiredTime = ((3 * 60 * 1000L) * 24) * 60;

    @PostConstruct
    protected void init() {
        secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
    }

    protected String createToken(String name, T type) {
        Map<String, Object> claims = new HashMap<>();
        claims.put(name, type);

        Date now = new Date();
        return Jwts.builder().setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(new Date(now.getTime() + expiredTime))
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .compact();
    }

    @SuppressWarnings("unchecked")
    protected T getKey(String token, String key) {
        Claims body = Jwts.parser()
                .setSigningKey(secretKey)
                .parseClaimsJws(token)
                .getBody();
        validate(body, key);

        return (T) body.get(key);
    }

    public String resolveToken(HttpServletRequest request, String name) {
        Optional<Cookie> jwtToken = Arrays.stream(request.getCookies())
                .filter(cookie -> cookie.getName().equals(name))
                .findFirst();
        if (jwtToken.isEmpty()) return null;

        return jwtToken.get().getValue();
    }

    protected abstract T validate(Claims type, String key);
}
