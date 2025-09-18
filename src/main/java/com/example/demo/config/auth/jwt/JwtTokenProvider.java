package com.example.demo.config.auth.jwt;


import com.example.demo.config.auth.PrincipalDetails;
import com.example.demo.domain.entity.JWTToken;
import com.example.demo.domain.entity.Signature;
import com.example.demo.domain.entity.User;
import com.example.demo.domain.repository.JWTTokenRepository;
import com.example.demo.domain.repository.SignatureRepository;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import jakarta.annotation.PostConstruct;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.stream.Collectors;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwtTokenProvider {

    private final SignatureRepository signatureRepository;
    private final JWTTokenRepository jwtTokenRepository;
    private final HttpServletResponse response;
    private final JwtProperties jwtProperties;

    private Key key;

    // ============================== Key 초기화 ==============================
    @PostConstruct
    public void init() {
        List<Signature> list = signatureRepository.findAll();
        if (list.isEmpty()) {
            byte[] keyBytes = KeyGenerator.getKeyGen();
            this.key = Keys.hmacShaKeyFor(keyBytes);

            // 초기화용 Signature 객체 생성
            Signature signature = new Signature();
            signature.setKeyByte(keyBytes);
            signature.setDate(LocalDate.now());

            log.info("[JwtTokenProvider] 최초 Key 생성 완료: {}", key);

            // email이 null이면 저장하지 않음
            if (signature.getEmail() != null) {
                signatureRepository.save(signature);
            } else {
                log.warn("[JwtTokenProvider] email이 null이므로 DB에 저장하지 않음");
            }
        } else {
            Signature signature = list.get(0);
            this.key = Keys.hmacShaKeyFor(signature.getKeyByte());
            log.info("[JwtTokenProvider] DB Key 로드 완료: {}", key);
        }
    }

    // ============================== 토큰 생성 ==============================
    public TokenInfo generateToken(Authentication authentication) {
        PrincipalDetails principal = (PrincipalDetails) authentication.getPrincipal();

        String authorities = authentication.getAuthorities().stream()
                .map(GrantedAuthority::getAuthority)
                .collect(Collectors.joining(","));

        long now = new Date().getTime();

        // ------------------- Access Token -------------------
        Date accessExpiry = new Date(now + jwtProperties.getAccessTokenExpiresIn());
        String accessToken = Jwts.builder()
                .setSubject(principal.getUsername())
                .claim("role", principal.getUser().getRole().name())
                .claim("provider", principal.getUser().getProvider())
                .claim("providerId", principal.getUser().getProviderId())
                .claim("auth", authorities)
                .setExpiration(accessExpiry)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        // ------------------- Refresh Token -------------------
        Date refreshExpiry = new Date(now + jwtProperties.getRefreshTokenExpiresIn());
        String refreshToken = Jwts.builder()
                .setSubject(principal.getUsername())
                .setExpiration(refreshExpiry)
                .signWith(key, SignatureAlgorithm.HS256)
                .compact();

        // ------------------- DB 저장 -------------------
        JWTToken jwtToken = jwtTokenRepository
                .findByEmailAndProvider(principal.getUsername(), principal.getUser().getProvider())
                .orElse(JWTToken.builder()
                        .email(principal.getUsername())
                        .provider(principal.getUser().getProvider())
                        .build());

        jwtToken.setAccessToken(accessToken);
        jwtToken.setRefreshToken(refreshToken);
        jwtToken.setIssuedAt(LocalDateTime.now());

        jwtTokenRepository.save(jwtToken);

        return TokenInfo.builder()
                .grantType(JwtProperties.TOKEN_PREFIX.trim())
                .accessToken(accessToken)
                .refreshToken(refreshToken)
                .build();
    }

    // ============================== Authentication 추출 ==============================
    public Authentication getAuthentication(String token) {
        Claims claims = parseClaims(token);

        if (claims.get("auth") == null) {
            throw new RuntimeException("권한 정보가 없는 토큰입니다.");
        }

        Collection<? extends GrantedAuthority> authorities = Arrays.stream(claims.get("auth").toString().split(","))
                .map(SimpleGrantedAuthority::new)
                .collect(Collectors.toList());

        // ✅ Builder를 활용해 User 객체 생성 (토큰 복원용 최소 데이터만 세팅)
        User user = User.builder()
                .email(claims.getSubject())  // subject = email
                .role(User.Role.valueOf(claims.get("role", String.class)))
                .provider(claims.get("provider", String.class))
                .providerId(claims.get("providerId", String.class))
                .build();

        PrincipalDetails principal = new PrincipalDetails(user);

        return new UsernamePasswordAuthenticationToken(principal, "", authorities);
    }

    // ============================== Token 유효성 검증 + 자동 재발급 ==============================
    public boolean validateToken(String token) {
        try {
            parseClaims(token);
            return true;
        } catch (ExpiredJwtException e) {
            log.info("Access Token 만료: {}", e.getMessage());

            JWTToken jwtEntity = jwtTokenRepository.findByAccessToken(token);
            if (jwtEntity != null) {
                String refreshToken = jwtEntity.getRefreshToken();
                if (validateRefreshToken(refreshToken)) {
                    Authentication auth = getAuthentication(refreshToken);
                    TokenInfo newTokens = generateToken(auth);

                    jwtEntity.setAccessToken(newTokens.getAccessToken());
                    jwtEntity.setRefreshToken(newTokens.getRefreshToken());
                    jwtTokenRepository.save(jwtEntity);

                    Cookie cookie = new Cookie(JwtProperties.COOKIE_NAME, newTokens.getAccessToken());
                    cookie.setPath("/");
                    cookie.setMaxAge((int) (jwtProperties.getAccessTokenExpiresIn() / 1000));
                    response.addCookie(cookie);

                    return true;
                } else {
                    log.info("Refresh Token 만료! 로그인 필요");
                    return false;
                }
            } else {
                log.info("DB에 JWT 정보 없음. 로그인 필요");
                return false;
            }
        } catch (JwtException | IllegalArgumentException ex) {
            log.error("잘못된 토큰", ex);
        }

        return false;
    }

    private boolean validateRefreshToken(String refreshToken) {
        try {
            Jwts.parser().setSigningKey(key).build().parseSignedClaims(refreshToken);
            return true;
        } catch (JwtException | IllegalArgumentException e) {
            return false;
        }
    }


    protected Claims parseClaims(String token) {
        try {
            return Jwts.parser().setSigningKey(key).build().parseClaimsJws(token).getBody();
        } catch (ExpiredJwtException e) {
            return e.getClaims();
        }
    }
}
