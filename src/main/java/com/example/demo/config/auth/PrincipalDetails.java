package com.example.demo.config.auth;

import com.example.demo.domain.entity.User;
import lombok.Data;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.oauth2.core.user.OAuth2User;

import java.util.Collection;
import java.util.Collections;
import java.util.Map;

@Data
public class PrincipalDetails implements UserDetails, OAuth2User {

    private final User user;
    private String accessToken;
    private Map<String, Object> attributes;   // OAuth2 정보 저장

    // 일반 login
    public PrincipalDetails(User user) {
        this.user = user;
    }

    // OAuth2 login
    public PrincipalDetails(User user, Map<String, Object> attributes){
        this.user = user;
        this.attributes = attributes;
    }


    // ==============================
    // UserDetails 구현 메서드 (Form 로그인)
    // ==============================
    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return Collections.singleton((GrantedAuthority) () -> "ROLE_" + user.getRole().name());
    }

    @Override
    public String getPassword() {
        return user.getPasswordHash();
    }

    @Override
    public String getUsername() {
        return user.getEmail();
    }

    @Override
    public boolean isAccountNonExpired() {
        return true;                    // 계정 만료 여부
    }

    @Override
    public boolean isAccountNonLocked() {
        return true;                    // 계정 잠김 여부
    }

    @Override
    public boolean isCredentialsNonExpired() {
        return true;                    // 비밀번호 만료 여부
    }

    @Override
    public boolean isEnabled() {
        return user.isActive();         // 계정 활성화 여부
    }


    // ==============================
    // OAuth2User 구현 메서드 (OAuth 로그인)
    // ==============================
    @Override
    public Map<String, Object> getAttributes() {
        return attributes;
    }

    @Override
    public String getName() {
        return user.getEmail();
    }
}
