package com.onesik.security.domain;

import lombok.*;
import org.springframework.data.annotation.CreatedDate;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import java.time.LocalDateTime;

import static lombok.AccessLevel.PROTECTED;

@Entity
@Getter
@NoArgsConstructor(access = PROTECTED)
@AllArgsConstructor
@Builder
@EqualsAndHashCode(of = "phoneNo")
public class User {

    @Id
    @GeneratedValue
    @Column(name = "user_id")
    private Long id;
    private String username;
    private String phoneNo;
    private String birthDate;
    @Column(columnDefinition = "TEXT")
    private String jwtToken;

    @CreatedDate
    private LocalDateTime creatDateTime;

    public User(String username, String phoneNo, String birthDate) {
        this.username = username;
        this.phoneNo = phoneNo;
        this.birthDate = birthDate;
        this.creatDateTime = LocalDateTime.now();
    }

    public void updateJwtToken(String jwtToken) {
        this.jwtToken = jwtToken;
    }
}
