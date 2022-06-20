package com.onesik.springsecurity.service;

import com.onesik.springsecurity.domain.User;
import com.onesik.springsecurity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
public class UserService {

    private final UserRepository repository;

    public User findByPhoneNo(String phoneNo) {
        return repository.findByPhoneNo(phoneNo);
    }

}
