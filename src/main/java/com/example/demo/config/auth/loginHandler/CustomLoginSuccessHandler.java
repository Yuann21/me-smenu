package com.example.demo.config.auth.loginHandler;

import com.example.demo.config.auth.jwt.JwtProperties;
import com.example.demo.config.auth.jwt.JwtTokenProvider;
import com.example.demo.config.auth.jwt.TokenInfo;
import com.example.demo.domain.entity.JWTToken;
import com.example.demo.domain.repository.JWTTokenRepository;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Collection;
import java.util.Optional;

@Slf4j
@Component
@RequiredArgsConstructor
public class CustomLoginSuccessHandler implements AuthenticationSuccessHandler {

    private final JwtTokenProvider jwtTokenProvider;
    private final JWTTokenRepository jwtTokenRepository;
    private final JwtProperties jwtProperties;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        String email = authentication.getName();
        String provider = "local";
        log.info("✅ 일반 로그인 성공: {}", email);

        // 기존 토큰 조회
        Optional<JWTToken> dbTokenOpt = jwtTokenRepository.findByEmailAndProvider(email, provider);
        TokenInfo tokenInfo;

        if (dbTokenOpt.isPresent() && jwtTokenProvider.validateToken(dbTokenOpt.get().getAccessToken())) {
            // 기존 유효 토큰 재사용
            JWTToken dbToken = dbTokenOpt.get();
            tokenInfo = new TokenInfo("Bearer", dbToken.getAccessToken(), dbToken.getRefreshToken());
            log.info("♻️ 기존 유효 토큰 재사용");
        } else {
            // 기존 토큰 없음 or 만료됨 → 새 발급
            dbTokenOpt.ifPresent(oldToken -> jwtTokenRepository.deleteById(oldToken.getId()));

            tokenInfo = jwtTokenProvider.generateToken(authentication);

            JWTToken newToken = JWTToken.builder()
                    .accessToken(tokenInfo.getAccessToken())
                    .refreshToken(tokenInfo.getRefreshToken())
                    .email(email)
                    .provider(provider)
                    .issuedAt(LocalDateTime.now())
                    .build();

            jwtTokenRepository.save(newToken);
            log.info("🆕 새 토큰 발급 및 저장");
        }

        // JWT → Cookie 전달
        Cookie cookie = new Cookie(JwtProperties.COOKIE_NAME, tokenInfo.getAccessToken());
        cookie.setMaxAge((int) (jwtProperties.getAccessTokenExpiresIn() / 1000)); // ms → sec 변환
        cookie.setPath("/");
        cookie.setHttpOnly(true);
        response.addCookie(cookie);

        // 권한별 redirect
        Collection<? extends GrantedAuthority> roles = authentication.getAuthorities();
        for (GrantedAuthority role : roles) {
            switch (role.getAuthority()) {
                case "ROLE_ADMIN" -> {
                    response.sendRedirect("/admin");
                    return;
                }
                case "ROLE_USER" -> {
                    response.sendRedirect("/user");
                    return;
                }
            }
        }

        response.sendRedirect("/");
    }
}
