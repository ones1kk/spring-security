package com.onesik.springsecurity;

import com.onesik.springsecurity.domain.User;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import javax.annotation.PostConstruct;
import javax.persistence.EntityManager;

@Component
@RequiredArgsConstructor
@Transactional
public class InitData {

    private final InitService service;

    @PostConstruct
    public void init() {
        service.dbInit();
    }

    @Component
    @Transactional
    @RequiredArgsConstructor
    static class InitService {

        private final EntityManager em;

        public void dbInit() {
          User user = new User("user1", "01012341234", "950201");
          em.persist(user);
        }

    }
}
