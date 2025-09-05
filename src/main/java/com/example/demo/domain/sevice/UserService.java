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



    public User registerUser(UserDto dto, String email) {
        // 로컬 계정 중복 확인 (email+provider)
        userRepository.findByEmailAndProvider(email, "local")
                .ifPresent(u -> { throw new IllegalArgumentException("이미 가입된 이메일입니다."); });


        // 2. User 엔티티로 변환 및 비밀번호 암호화, 기본 USER role 부여
        User user = User.builder()
                .email(dto.getEmail())
                .nickname(dto.getNickname())
                .passwordHash(passwordEncoder.encode(dto.getPassword()))
                .role(User.Role.USER)
                .isActive(true)             // DB에 is_active = 1로 들어감(true)
                .provider("local")          // local 고정
                .providerId(null)           // local은 null
                .build();

        // 3. 엔티티 저장
        return userRepository.save(user);

    }


}
