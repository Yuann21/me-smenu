package com.example.demo.config.auth.logoutHandler;

import com.example.demo.config.auth.jwt.JwtProperties;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.util.Arrays;

@Slf4j
@Component
public class CustomLogoutSuccessHandler implements LogoutSuccessHandler {

    @Value("${KAKAO_CLIENT_ID}")
    private String kakaoClientId;

    @Value("${spring.security.oauth2.client.registration.kakao.redirect-uri}")
    private String kakaoLogoutRedirectUri;

    @Override
    public void onLogoutSuccess(HttpServletRequest request,
                                HttpServletResponse response,
                                Authentication authentication) throws IOException, ServletException {

        log.info("➡️ CustomLogoutSuccessHandler 실행");

        // 1️⃣ JWT 쿠키 삭제
        if (request.getCookies() != null) {
            Arrays.stream(request.getCookies())
                    .filter(cookie -> JwtProperties.COOKIE_NAME.equals(cookie.getName()))
                    .forEach(cookie -> {
                        cookie.setMaxAge(0);
                        cookie.setPath("/");
                        response.addCookie(cookie);
                        log.info("JWT 쿠키 삭제 완료");
                    });
        }

        // 2️⃣ Provider별 Redirect
        if (authentication != null) {
            Object principal = authentication.getPrincipal();
            if (principal instanceof com.example.demo.config.auth.PrincipalDetails principalDetails) {
                String provider = principalDetails.getUser().getProvider();
                log.info("로그아웃 Redirect 처리: provider={}", provider);

                switch (provider.toLowerCase()) {
                    case "kakao" -> {
                        response.sendRedirect("https://kauth.kakao.com/oauth/logout?client_id=" + kakaoClientId +
                                "&logout_redirect_uri=" + kakaoLogoutRedirectUri);
                        return;
                    }
                    case "naver" -> {
                        response.sendRedirect("https://nid.naver.com/nidlogin.logout?returl=https://www.naver.com/");
                        return;
                    }
                    case "google" -> {
                        response.sendRedirect("https://accounts.google.com/Logout");
                        return;
                    }
                    default -> log.info("Provider 매칭 없음, 기본 Redirect 수행");
                }
            }
        }

        // 3️⃣ 기본 fallback
        response.sendRedirect("/");
    }
}
