package com.example.demo.config.auth.logoutHandler;

import com.example.demo.config.auth.PrincipalDetails;
import com.example.demo.config.auth.jwt.JwtProperties;
import com.example.demo.config.auth.jwt.JwtTokenProvider;
import com.example.demo.domain.repository.JWTTokenRepository;
import com.example.demo.domain.sevice.OAuthUnlinkService;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

import java.util.Arrays;

@Slf4j
public class CustomLogoutHandler implements LogoutHandler {

    private final JwtTokenProvider jwtTokenProvider;
    private final JWTTokenRepository jwtTokenRepository;
    private final OAuthUnlinkService oAuthUnlinkService;
    private final PersistentTokenRepository persistentTokenRepository;
    private final String naverClientId;
    private final String naverClientSecret;

    public CustomLogoutHandler(JwtTokenProvider jwtTokenProvider,
                               JWTTokenRepository jwtTokenRepository,
                               OAuthUnlinkService oAuthUnlinkService,
                               PersistentTokenRepository persistentTokenRepository,
                               String naverClientId,
                               String naverClientSecret) {
        this.jwtTokenProvider = jwtTokenProvider;
        this.jwtTokenRepository = jwtTokenRepository;
        this.oAuthUnlinkService = oAuthUnlinkService;
        this.persistentTokenRepository = persistentTokenRepository;
        this.naverClientId = naverClientId;
        this.naverClientSecret = naverClientSecret;
    }

    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {

        log.info("➡️ CustomLogoutHandler 시작");

        // 1️⃣ 쿠키에서 JWT 가져오기
        String token = null;
        if (request.getCookies() != null) {
            token = Arrays.stream(request.getCookies())
                    .filter(c -> JwtProperties.COOKIE_NAME.equals(c.getName()))
                    .map(Cookie::getValue)
                    .findFirst()
                    .orElse(null);
        }

        // 2️⃣ Authentication 확인
        Authentication auth = authentication;
        if (auth == null && token != null) {
            auth = jwtTokenProvider.getAuthentication(token);
        }

        if (auth == null) {
            log.warn("⚠️ Authentication 없음 -> 로그아웃 처리 제한");
        } else if (auth.getPrincipal() instanceof PrincipalDetails principalDetails) {
            String provider = principalDetails.getUser().getProvider();
            String email = principalDetails.getUser().getEmail();
            String accessToken = principalDetails.getAccessToken();

            log.info("로그아웃 처리: provider={}, email={}", provider, email);

            // 3️⃣ DB JWT 삭제
            jwtTokenRepository.findByEmailAndProvider(email, provider)
                    .ifPresent(tokenEntity -> {
                        jwtTokenRepository.deleteById(tokenEntity.getId());
                        log.info("DB JWT 삭제 완료 -> {}", email);
                    });

            // 4️⃣ Remember-me 토큰 삭제
            persistentTokenRepository.removeUserTokens(email);

            // 5️⃣ OAuth unlink 호출
            if (provider != null && accessToken != null) {
                switch (provider) {
                    case "kakao" -> oAuthUnlinkService.logoutKakao(accessToken);
                    case "naver" -> oAuthUnlinkService.logoutNaver(accessToken, naverClientId, naverClientSecret);
                    case "google" -> oAuthUnlinkService.logoutGoogle(accessToken);
                    default -> log.warn("알 수 없는 provider={}", provider);
                }
            }
        }

        // 6️⃣ 세션 무효화
        HttpSession session = request.getSession(false);
        if (session != null) {
            session.invalidate();
            log.info("세션 무효화 완료");
        }

        // 7️⃣ SecurityContext 초기화
        SecurityContextHolder.clearContext();
        log.info("SecurityContext 초기화 완료");
    }
}
