package com.example.demo.domain.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@AllArgsConstructor
@NoArgsConstructor
@Builder
public class UserDto {
    private String nickname;
    private String email;
    private String password;

    // social login
    private String provider;             // "google", "kakao", "naver"
    private String providerId;           // social에서 제공하는 PK
}
