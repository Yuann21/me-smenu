package com.example.demo.config.auth.jwt;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@AllArgsConstructor
public class TokenInfo {
    private String grantType;     // 인증 받는 종류. ex) "Bearer"
    private String accessToken;
    private String refreshToken;
}
