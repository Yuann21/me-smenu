package com.example.demo.domain.sevice;


import com.example.demo.domain.dto.UserDto;
import com.example.demo.domain.entity.User;
import com.example.demo.domain.repository.UserRepository;
import lombok.AllArgsConstructor;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.stereotype.Service;

@Service
@AllArgsConstructor
public class UserService {
    private final UserRepository userRepository;
    private final PasswordEncoder passwordEncoder;



    public User registerUser(UserDto dto) {
        // 1. 이메일 중복 체크
        if (userRepository.existsByEmail(dto.getEmail())) {
            throw new IllegalArgumentException("이미 사용 중인 이메일입니다.");
        }

        // 2. User 엔티티로 변환 및 비밀번호 암호화, 기본 USER role 부여
        User user = User.builder()
                .email(dto.getEmail())
                .nickname(dto.getNickname())
                .passwordHash(passwordEncoder.encode(dto.getPassword()))
                .role(User.Role.USER)
                .build();

        // 3. 엔티티 저장
        return userRepository.save(user);

    }

    // 비밀번호 검증 테스트용
    public boolean checkPassword(String rawPassword, String email) {
        User user = userRepository.findByEmail(email)
                .orElseThrow(() -> new IllegalArgumentException("User not found"));
        return passwordEncoder.matches(rawPassword, user.getPasswordHash());
    }
}
