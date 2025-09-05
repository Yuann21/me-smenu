package com.example.demo.domain.entity;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.LocalDateTime;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
@Entity
@Table(
        name = "users",
        uniqueConstraints = {
                @UniqueConstraint(columnNames = {"email", "provider"}) // email + provider 조합 unique
        }
)
public class User {



    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY) // Auto-Increment
    @Column(name = "id")
    private Long id;    // UUID는 나중에 헤봄

    @Column(nullable = false, length = 255)
    private String email;

    @Column(name = "password_hash", nullable = false, length = 255)
    private String passwordHash;

    @Column(nullable = false, length = 50)
    private String nickname;

    @Column(name = "profile_image_url", length = 500)
    private String profileImageUrl;

    @Enumerated(EnumType.STRING)
    @Column(nullable = false, length = 10)
    private Role role = Role.USER;

    @Column(name = "is_active", nullable = false)
    private boolean isActive = true;

    @Column(length = 10)
    private String locale = "ko";

    @Column(length = 50)
    private String timezone = "Asia/Seoul";

    @Column(name = "notif_morning_time")
    private String notifMorningTime; // TIME 타입: HH:mm:ss 형식 문자열

    @Column(name = "notif_evening_time")
    private String notifEveningTime;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    @Column(name = "last_login_at")
    private LocalDateTime lastLoginAt;

    public enum Role {
        USER,
        ADMIN
    }

    // OAUTH2
    @Column(nullable = false, length = 50)
    private String provider;   // google, kakao, naver

    @Column(length = 100)
    private String providerId; // 각 provider에서 제공하는 unique id

}
