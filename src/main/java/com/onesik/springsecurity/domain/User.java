package com.onesik.springsecurity.domain;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;
import org.springframework.data.annotation.CreatedDate;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import java.time.LocalDateTime;

import static lombok.AccessLevel.PROTECTED;

@Entity
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
    private String jwtToken;

    @CreatedDate
    private LocalDateTime creatDateTime;

    public User(String username, String phoneNo, String birthDate) {
        this.username = username;
        this.phoneNo = phoneNo;
        this.birthDate = birthDate;
        this.creatDateTime = LocalDateTime.now();
    }
}
