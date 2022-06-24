package com.onesik.security.web.jwt;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.jsonwebtoken.Claims;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
public class AuthenticationTypeJwtTokenProvider extends AbstractJwtTokenProvider<Authentication> {

    public AuthenticationTypeJwtTokenProvider(ObjectMapper objectMapper) {
        super(objectMapper);
    }

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
