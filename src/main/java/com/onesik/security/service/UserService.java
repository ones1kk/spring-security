package com.onesik.security.service;

import com.onesik.security.domain.User;
import com.onesik.security.repository.UserRepository;
import com.onesik.security.web.exception.NotFoundUserException;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.Optional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class UserService {

    private final UserRepository repository;

    public User findByPhoneNo(String phoneNo) {
        return repository.findByPhoneNo(phoneNo);
    }

    public User findById(Long id) {
        return repository.findById(id).orElseThrow();
    }

    @Transactional
    public void updateUserJwtToken(String jwtToken, Long userId) {
        User user = repository.findById(userId).orElseThrow(() -> new NotFoundUserException("Not Found"));
        user.updateJwtToken(jwtToken);
    }
}
