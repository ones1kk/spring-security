package com.onesik.security.repository;

import com.onesik.security.domain.SmsHistory;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SmsHistoryRepository extends JpaRepository<SmsHistory, Long> {
    SmsHistory findByUserId(Long userId);
}
