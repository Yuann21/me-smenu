package com.example.demo.domain.entity;

import jakarta.persistence.*;
import lombok.Data;

import java.time.LocalDate;

@Entity
@Data
public class Signature {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Lob
    private byte[] keyByte;

    private LocalDate date;

    // JWT/사용자 식별용 필드 추가
    @Column(nullable = false)
    private String email;

    @Column(nullable = false)
    private String provider;
}