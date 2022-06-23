package com.onesik.springsecurity.web.jwt;

import io.jsonwebtoken.Claims;

public class StringTypeJwtProvider extends AbstractJwtProvider<String> {

    // TODO write defense logic
    @Override
    protected String validate(Claims type, String key) {
        return null;
    }
}
