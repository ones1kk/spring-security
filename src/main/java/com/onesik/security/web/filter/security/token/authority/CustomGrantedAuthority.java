package com.onesik.security.web.filter.security.token.authority;

import com.fasterxml.jackson.annotation.JsonValue;
import io.jsonwebtoken.lang.Assert;
import org.springframework.security.core.GrantedAuthority;

public class CustomGrantedAuthority implements GrantedAuthority {

    @JsonValue
    private final String role;

    public CustomGrantedAuthority(String role) {
        Assert.hasText(role, "A granted authority textual representation is required");
        this.role = role;
    }

    @Override
    public String getAuthority() {
        return this.role;
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        }
        if (obj instanceof CustomGrantedAuthority) {
            return this.role.equals(((CustomGrantedAuthority) obj).role);
        }
        return false;
    }

    @Override
    public int hashCode() {
        return this.role.hashCode();
    }

    @Override
    public String toString() {
        return this.role;
    }

}
