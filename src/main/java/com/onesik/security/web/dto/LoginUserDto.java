package com.onesik.security.web.dto;

import com.onesik.security.domain.User;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;

@Getter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class LoginUserDto {

    private String username;
    private String birthDate;
    private String phoneNo;

    public User toEntity() {
        return User.builder()
                .username(this.username)
                .birthDate(this.birthDate)
                .phoneNo(this.phoneNo)
                .build();
    }
}
