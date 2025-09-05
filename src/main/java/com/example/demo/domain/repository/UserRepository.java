package com.example.demo.domain.repository;

import com.example.demo.domain.entity.User;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<User, Long> {

    // 이메일 중복 체크
//    boolean existsByEmail(String email);

//    // 로그인 시 사용자 조회
//    Optional<User> findByEmail(String email);

    // email + provider 조합으로 사용자 찾기
    Optional<User> findByEmailAndProvider(String email, String provider);

    // 회원 탈퇴 시
    void deleteByEmail(String email);
}
