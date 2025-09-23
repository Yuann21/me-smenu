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
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Collection;
import java.util.Map;

@Slf4j
@Component
@RequiredArgsConstructor
public class Oauth2JwtLoginSuccessHandler implements AuthenticationSuccessHandler {

    private final JwtTokenProvider jwtTokenProvider;
    private final JWTTokenRepository jwtTokenRepository;
    private final JwtProperties jwtProperties;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        OAuth2AuthenticationToken oauthToken = (OAuth2AuthenticationToken) authentication;
        OAuth2User oauthUser = (OAuth2User) oauthToken.getPrincipal();
        String provider = oauthToken.getAuthorizedClientRegistrationId().toLowerCase();
        Map<String, Object> attributes = oauthUser.getAttributes();

        // ------------------- Email 추출 -------------------
        String email = null;
        switch (provider) {
            case "google" -> email = (String) attributes.get("email");
            case "kakao" -> {
                Map<String, Object> kakaoAccount = (Map<String, Object>) attributes.get("kakao_account");
                if (kakaoAccount != null) email = (String) kakaoAccount.get("email");
            }
            case "naver" -> {
                Map<String, Object> naverResp = (Map<String, Object>) attributes.get("response");
                if (naverResp != null) email = (String) naverResp.get("email");
            }
        }

        log.info("✅ OAuth2 로그인 성공: email={}, provider={}", email, provider);

        // ------------------- 세션 무효화 -------------------
        request.getSession().invalidate();

        // ------------------- 새 토큰 발급 -------------------
        TokenInfo tokenInfo = jwtTokenProvider.generateToken(authentication);

        // ------------------- DB 저장 -------------------
        JWTToken newToken = JWTToken.builder()
                .email(email)
                .provider(provider)
                .accessToken(tokenInfo.getAccessToken())
                .refreshToken(tokenInfo.getRefreshToken())
                .issuedAt(LocalDateTime.now())
                .build();
        jwtTokenRepository.save(newToken);
        log.info("🆕 새 OAuth2 토큰 발급 및 DB 저장");

        // ------------------- 쿠키 세팅 -------------------
        Cookie cookie = new Cookie(JwtProperties.COOKIE_NAME, tokenInfo.getAccessToken());
        cookie.setHttpOnly(true);
        cookie.setPath("/");
        cookie.setMaxAge((int) (jwtProperties.getAccessTokenExpiresIn() / 1000));
        response.addCookie(cookie);

        // ------------------- 권한 기반 리다이렉트 -------------------
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

        // 기본 리다이렉트
        response.sendRedirect("/");
    }
}
