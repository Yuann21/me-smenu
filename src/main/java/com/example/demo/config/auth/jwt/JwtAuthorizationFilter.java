package com.example.demo.config.auth.jwt;

import com.example.demo.config.auth.PrincipalDetails;
import com.example.demo.domain.entity.User;
import com.example.demo.domain.repository.UserRepository;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Optional;

@Slf4j
@RequiredArgsConstructor
public class JwtAuthorizationFilter extends OncePerRequestFilter {
                                            // 한 요청당 한 번 실행
    private final JwtTokenProvider jwtTokenProvider;
    private final UserRepository userRepository;

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        // ------------------- 토큰 추출 -------------------
        String token = resolveToken(request);  // HTTP 요청에서 JWT 토큰을 꺼내

        if (token != null) {
            try {
                boolean valid = jwtTokenProvider.validateToken(token); // AccessToken 유효성 검사 + 재발급
                if (valid) {
                    // 토큰이 유효하면, 토큰 정보를 기반으로 Authentication 객체 생성.
                    Authentication auth = jwtTokenProvider.getAuthentication(token);

                    // DB에서 실제 User 존재 여부 체크
                    Optional<User> user = userRepository.findByEmailAndProvider(auth.getName(),
                            ((PrincipalDetails) auth.getPrincipal()).getUser().getProvider());
                    if (user.isPresent()) {
                        SecurityContextHolder.getContext().setAuthentication(auth);
                        log.info("[JWT] Authentication set for user: {}", auth.getName());
                    } else {
                        log.warn("[JWT] User not found in DB: {}", auth.getName());
                    }
                }
            }catch (Exception e) {
                log.warn("[JWT] Token validation failed: {}", e.getMessage());
            }
        }


        filterChain.doFilter(request, response);
    }

    // ------------------- 토큰 헤더/쿠키에서 추출 -------------------
    private String resolveToken(HttpServletRequest request) {
        // Authorization Header에서 먼저 찾음
        String bearerToken = request.getHeader(JwtProperties.HEADER_STRING);
        if (bearerToken != null && bearerToken.startsWith(JwtProperties.TOKEN_PREFIX)) {
            return bearerToken.substring(JwtProperties.TOKEN_PREFIX.length());
        }

        // Cookie : 없으면 Cookie 에서 찾음 (웹 지원)
        if (request.getCookies() != null) {
            for (Cookie cookie : request.getCookies()) {
                if (JwtProperties.COOKIE_NAME.equals(cookie.getName())) {
                    return cookie.getValue();
                }
            }
        }
        return null;         // 못 찾으면 null
    }
}
