package com.example.demo.config.auth.jwt;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;


@Component
@ConfigurationProperties(prefix = "jwt")
public class JwtProperties {
    // ✅ 고정 상수
    public static final String TOKEN_PREFIX = "Bearer ";
    public static final String HEADER_STRING = "Authorization";
    public static final String COOKIE_NAME = "JWT_TOKEN";

    // ✅ 환경설정에서 주입받는 값
    @Value("${jwt.access-token-validity-in-ms}")
    private long accessTokenExpiresIn;

    @Value("${jwt.refresh-token-validity-in-ms}")
    private long refreshTokenExpiresIn;

    // ✅ Getter 추가
    public long getAccessTokenExpiresIn() {
        return accessTokenExpiresIn;
    }

    public long getRefreshTokenExpiresIn() {
        return refreshTokenExpiresIn;
    }
}
