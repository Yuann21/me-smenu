package com.example.demo.config.auth.jwt;

import java.security.SecureRandom;

public class KeyGenerator {

    // 256비트 난수 키 생성
    public static byte[] getKeyGen() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] keyBytes = new byte[256 / 8]; // 256비트 키 생성 (32바이트)
        secureRandom.nextBytes(keyBytes);    // 난수로 바이트 배열 생성
        System.out.println("KeyGenerator getKeygen Key: " + keyBytes);
        return keyBytes;
    }
}
