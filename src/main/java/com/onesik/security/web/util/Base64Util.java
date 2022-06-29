package com.onesik.security.web.util;

import lombok.AllArgsConstructor;
import lombok.Getter;

public class Base64Util {

    public static String decodeWhitespace(String decodedMessage) {
        return decodedMessage.replace(Characters.ENCODED.getValue(), Characters.WHITE_SPACE.getValue());
    }

    @Getter
    @AllArgsConstructor
    private enum Characters {
        ENCODED("%"),
        WHITE_SPACE(" ");

        private final String value;

    }

}
