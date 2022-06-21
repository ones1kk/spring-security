package com.onesik.springsecurity.service;

import com.onesik.springsecurity.domain.User;
import com.onesik.springsecurity.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import javax.persistence.EntityNotFoundException;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class UserService {

    private final UserRepository repository;

    public User findByPhoneNo(String phoneNo) {
        return repository.findByPhoneNo(phoneNo);
    }

    @Transactional
    public void updateUserJwtToken(String jwtToken, Long userId) {
        User user = repository.findById(userId).orElseThrow(() -> new EntityNotFoundException("Not Found"));
        user.updateJwtToken(jwtToken);
    }
}
