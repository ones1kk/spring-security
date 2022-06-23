package com.onesik.springsecurity.service;

import com.onesik.springsecurity.domain.User;
import com.onesik.springsecurity.repository.UserRepository;
import com.onesik.springsecurity.web.exception.NotFoundUserException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

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
        User user = repository.findById(userId).orElseThrow(() -> new NotFoundUserException("Not Found"));
        user.updateJwtToken(jwtToken);
    }
}
