package com.onesik.springsecurity.repository;

import com.onesik.springsecurity.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {
    User findByPhoneNo(String phoneNo);

}
