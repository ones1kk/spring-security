package com.onesik.security.web.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.onesik.security.domain.User;
import com.onesik.security.web.filter.security.token.FirstAuthenticationToken;
import com.onesik.security.web.filter.security.token.SecondAuthenticationToken;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jws;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.SignatureAlgorithm;
import io.jsonwebtoken.io.Serializer;
import io.jsonwebtoken.jackson.io.JacksonSerializer;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;

import javax.annotation.PostConstruct;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import java.util.*;
import java.util.stream.Stream;

@Component
@RequiredArgsConstructor
public class JwtTokenProvider<T> {

    private final ObjectMapper objectMapper;

    private String secretKey = "c88d74ba-1554-48a4-b549-b926f5d77c9e";

    public final static String X_AUTH_TOKEN = "X_AUTH_TOKEN";
    public final static String NAME = "name";

    private static final Serializer<Map<String, ?>> JWT_SERIALIZER = new JacksonSerializer<>(new ObjectMapper().registerModule(new JavaTimeModule()));

    // 3 Days
    protected static final long expiredTime = ((3 * 60 * 1000L) * 24) * 60;

    @PostConstruct
    protected void init() {
        secretKey = Base64.getEncoder().encodeToString(secretKey.getBytes());
    }

    public String createToken(T type, String name) {
        // TODO Refactor
        if (type instanceof String) {
            return createTokenSubject(name);
        }
        Map<String, Object> claims = new HashMap<>();
        claims.put(name, type);

        Date now = new Date();
        return getCompact(claims, now);
    }

    private String createTokenSubject(String name) {
        Claims claims = Jwts.claims().setSubject(name);
        Date now = new Date();
        return Jwts.builder()
                .serializeToJsonWith(JWT_SERIALIZER)
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(new Date(now.getTime() + expiredTime))
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .compact();
    }

    public String getErrorMessage(String jwtToken) {
        return Jwts.parser().setSigningKey(secretKey)
                .parseClaimsJws(jwtToken).getBody().getSubject();
    }

    @SuppressWarnings(value = {"ConstantConditions", "unchecked"})
    public T getKey(String jwtToken) {
        Claims body = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(jwtToken).getBody();
        Object authentication = body.get(X_AUTH_TOKEN);

        Optional<T> optional = (Optional<T>) Stream.of(authentication).filter(Objects::nonNull)
                .filter(auth -> auth instanceof Map)
                .map(auth -> (Map<?, ?>) auth)
                .filter(map -> map.containsKey(NAME))
                .map(map -> (String) map.get(NAME))
                .filter(StringUtils::hasText)
                .map(name -> getAbstractAuthenticationToken(authentication, name))
                .findFirst();

        return optional.orElse(null);
    }

    private AbstractAuthenticationToken getAbstractAuthenticationToken(Object authentication, String name) {
        switch (name) {
            case "FirstAuthenticationToken":
                FirstAuthenticationToken firstAuthenticationToken = objectMapper.convertValue(authentication, FirstAuthenticationToken.class);
                Object firstPrincipal = firstAuthenticationToken.getPrincipal();
                if (firstPrincipal instanceof Map) {
                    User user = objectMapper.convertValue(firstPrincipal, User.class);
                    firstAuthenticationToken.setPrincipal(user);
                    return firstAuthenticationToken;
                }
                return null;

            case "SecondAuthenticationToken":
                SecondAuthenticationToken secondAuthenticationToken = objectMapper.convertValue(authentication, SecondAuthenticationToken.class);
                Object SecondPrincipal = secondAuthenticationToken.getPrincipal();
                if (SecondPrincipal instanceof Map) {
                    User user = objectMapper.convertValue(SecondPrincipal, User.class);
                    secondAuthenticationToken.setPrincipal(user);
                    return secondAuthenticationToken;
                }
                return null;
            default:
                return null;
        }
    }

    public String resolveToken(HttpServletRequest request, String cookieName) {
        Optional<Cookie> token = Arrays.stream(request.getCookies())
                .filter(cookie -> cookie.getName().equals(cookieName))
                .findFirst();
        if (token.isEmpty()) return null;

        return token.get().getValue();
    }

    public boolean validateToken(String jwtToken) {
        try {
            Jws<Claims> claims = Jwts.parser().setSigningKey(secretKey).parseClaimsJws(jwtToken);
            return !claims.getBody().getExpiration().before(new Date());
        } catch (Exception e) {
            return false;
        }
    }

    public T resolveAndGet(HttpServletRequest request, String cookieName) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) return null;
        String jwtToken = resolveToken(request, cookieName);
        if (jwtToken == null) return null;
        return getKey(jwtToken);
    }

    private String getCompact(Map<String, Object> claims, Date now) {
        return Jwts.builder()
                .serializeToJsonWith(JWT_SERIALIZER)
                .setClaims(claims)
                .setIssuedAt(now)
                .setExpiration(new Date(now.getTime() + expiredTime))
                .signWith(SignatureAlgorithm.HS256, secretKey)
                .compact();
    }

}
