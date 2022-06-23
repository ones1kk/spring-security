package com.onesik.security.web.jwt;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import javax.annotation.PostConstruct;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.util.Arrays;
import java.util.Base64;
import java.util.Date;
import java.util.Optional;

@Component
@RequiredArgsConstructor
public class JwtProvider {

    private String secretKey = "c88d74ba-1554-48a4-b549-b926f5d77c9e";

    private final static String X_AUTH_TOKEN = "x-auth-token";

    // 3일
    private static final long expiredTime = ((3 * 60 * 1000L) * 24) * 60;

    @PostConstruct
    protected void init() {
        secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
    }

    // JWT 토큰 생성
    public String createToken(String phoneNo) {
        Claims claims = Jwts.claims().setSubject(phoneNo);

        Date now = new Date();
        return Jwts.builder()
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(new Date(now.getTime() + expiredTime))
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .compact();
    }

    // 토큰에서 회원 정보 추출
    public String getUserPhoneNo(String token) {
        return Jwts.parser().setSigningKey(secretKey).parseClaimsJws(token).getBody().getSubject();
    }

    public String resolveToken(HttpServletRequest request) {
        Optional<Cookie> jwtToken = Arrays.stream(request.getCookies())
                .filter(cookie -> cookie.getName().equals("X-AUTH-TOKEN"))
                .findFirst();
        if (jwtToken.isEmpty()) return null;

        return getUserPhoneNo(jwtToken.get().getValue());
    }

    public boolean validateToken(String jwtToken) {
        try {
            Jws<Claims> claims = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(jwtToken);
            return !claims.getBody().getExpiration().before(new Date());
        } catch (Exception e) {
            return false;
        }
    }

}
