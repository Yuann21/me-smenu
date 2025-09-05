package com.example.demo.config.auth;

import com.example.demo.domain.entity.User;
import com.example.demo.domain.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
@RequiredArgsConstructor
@Slf4j
public class PrincipalDetailsService implements UserDetailsService {

    private final UserRepository userRepository;
    private static final String LOCAL_PROVIDER = "local";

    @Override
    public UserDetails loadUserByUsername(String email) throws UsernameNotFoundException{

        log.info("Trying to load user: " + email); // 이메일 값 확인

        // 폼 로그인 계정의 경우 반드시 provider=local 로 조회
        User user = userRepository.findByEmailAndProvider(email, LOCAL_PROVIDER)
                .orElseThrow(() -> new UsernameNotFoundException("User not found: " + email));

        return new PrincipalDetails(user);
    }
}
