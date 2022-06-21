package com.onesik.springsecurity.service;

import com.onesik.springsecurity.domain.SmsHistory;
import com.onesik.springsecurity.repository.SmsHistoryRepository;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

@Service
@RequiredArgsConstructor
@Transactional(readOnly = true)
public class SmsHistoryService {

    private final SmsHistoryRepository repository;

    public SmsHistory findByUserId(Long userId) {
        return repository.findByUserId(userId);
    }

    @Transactional
    public void save(SmsHistory smsHistory) {
        repository.save(smsHistory);
    }
}
