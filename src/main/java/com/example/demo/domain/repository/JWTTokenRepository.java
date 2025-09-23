package com.example.demo.domain.repository;

import com.example.demo.domain.entity.JWTToken;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface JWTTokenRepository extends JpaRepository<JWTToken, Long> {

    // AccessToken 기준 조회
    JWTToken findByAccessToken(String accessToken);

    // Email + Provider 기준 조회 (OAuth2용)
    Optional<JWTToken> findByEmailAndProvider(String email, String provider);
}

