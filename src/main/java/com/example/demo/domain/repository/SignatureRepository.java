package com.example.demo.domain.repository;

import com.example.demo.domain.entity.JWTToken;
import com.example.demo.domain.entity.Signature;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface SignatureRepository extends JpaRepository<Signature, Long> {
    // 이메일 + provider 조합으로 토큰 찾기 (중복 방지 목적)
    Optional<JWTToken> findByEmailAndProvider(String email, String provider);
}

