package com.onesik.springsecurity.repository;

import com.onesik.springsecurity.domain.SmsHistory;
import org.springframework.data.jpa.repository.JpaRepository;

public interface SmsHistoryRepository extends JpaRepository<SmsHistory, Long> {
}
