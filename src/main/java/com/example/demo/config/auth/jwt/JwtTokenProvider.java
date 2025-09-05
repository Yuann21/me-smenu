//package com.example.demo.config.auth.jwt;
//
//
//import com.example.demo.domain.repository.UserRepository;
//import io.jsonwebtoken.Claims;
//import io.jsonwebtoken.ExpiredJwtException;
//import io.jsonwebtoken.Jwts;
//import io.jsonwebtoken.SignatureAlgorithm;
//import io.jsonwebtoken.security.Keys;
//import lombok.RequiredArgsConstructor;
//import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
//import org.springframework.security.core.userdetails.UserDetails;
//import org.springframework.security.core.userdetails.UserDetailsService;
//import org.springframework.stereotype.Component;
//
//import java.security.Key;
//
//@Component
//@RequiredArgsConstructor
//public class JwtTokenProvider {
//
//    private final UserDetailsService userDetailsService; // DB에서 UserDetails 조회
//    private final UserRepository userRepository;         // 필요 시 User 직접 조회
//
//    // JWT 서명 키
//    private final Key key = Keys.hmacShaKeyFor(JwtProperties.SECRET.getBytes());
//
//    // Access Token 생성
//    public String createAccessToken(String username, String role) {
//        return createToken(username, role, JwtProperties.ACCESS_TOKEN_EXPIRATION_TIME);
//    }
//
//    // Refresh Token 생성
//    public String createRefreshToken(String username) {
//        return createToken(username, null, JwtProperties.REFRESH_TOKEN_EXPIRATION_TIME);
//    }
//
//    // 공통 토큰 생성 메서드
//    private String createToken(String username, String role, long validityInMillis) {
//        Claims claims = Jwts.claims().setSubject(username); // sub = username
//        if (role != null) {
//            claims.put("role", role);
//        }
//
//        Date now = new Date();
//        Date expiry = new Date(now.getTime() + validityInMillis);
//
//        return Jwts.builder()
//                .setClaims(claims)
//                .setIssuedAt(now)
//                .setExpiration(expiry)
//                .signWith(key, SignatureAlgorithm.HS256)
//                .compact();
//    }
//
//    // JWT 토큰에서 Authentication 객체 생성
//    public Authentication getAuthentication(String token) {
//        String username = getUsername(token);
//        UserDetails userDetails = userDetailsService.loadUserByUsername(username);
//        return new UsernamePasswordAuthenticationToken(userDetails, "", userDetails.getAuthorities());
//    }
//
//    // 토큰에서 username(email) 추출
//    public String getUsername(String token) {
//        return parseClaims(token).getSubject();
//    }
//
//    // 토큰 유효성 검사
//    public boolean validateToken(String token) {
//        try {
//            parseClaims(token);
//            return true;
//        } catch (ExpiredJwtException e) {
//            System.out.println("[JwtTokenProvider] Token expired: " + e.getMessage());
//        } catch (JwtException | IllegalArgumentException e) {
//            System.out.println("[JwtTokenProvider] Invalid token: " + e.getMessage());
//        }
//        return false;
//    }
//
//    // Claim 파싱
//    private Claims parseClaims(String token) {
//        return Jwts.parserBuilder()
//                .setSigningKey(key)
//                .build()
//                .parseClaimsJws(token)
//                .getBody();
//    }
//}
