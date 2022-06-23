package com.onesik.security.repository;

import com.onesik.security.domain.User;
import org.springframework.data.jpa.repository.JpaRepository;

public interface UserRepository extends JpaRepository<User, Long> {
    User findByPhoneNo(String phoneNo);

}
