package com.onesik.springsecurity.web.jwt;

import io.jsonwebtoken.Claims;
import org.springframework.security.core.Authentication;

import java.util.Map;

public class AuthenticationTypeJwtProvider extends AbstractJwtProvider<Authentication> {

    // TODO write defense logic
    @Override
    protected Authentication validate(Claims type, String key) {
        Object object = type.get(key);

        if (object != null) {
            if (object instanceof Map) {
                Map<?, ?> map = (Map<?, ?>) object;
            }
            return null;
        }

        return null;
    }
}
