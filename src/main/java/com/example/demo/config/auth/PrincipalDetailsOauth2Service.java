package com.example.demo.config.auth;

import com.example.demo.config.auth.provider.GoogleUserInfo;
import com.example.demo.config.auth.provider.KakaoUserInfo;
import com.example.demo.config.auth.provider.NaverUserInfo;
import com.example.demo.config.auth.provider.OAuth2UserInfo;
import com.example.demo.domain.entity.User;
import com.example.demo.domain.repository.UserRepository;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.client.userinfo.DefaultOAuth2UserService;
import org.springframework.security.oauth2.client.userinfo.OAuth2UserRequest;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.user.OAuth2User;
import org.springframework.stereotype.Service;

import java.util.Map;

@Service
@Slf4j
@RequiredArgsConstructor
public class PrincipalDetailsOauth2Service extends DefaultOAuth2UserService {


    private final UserRepository userRepository;    // DB 접근용
    private final PasswordEncoder passwordEncoder;


    @Override
    public OAuth2User loadUser(OAuth2UserRequest userRequest) throws OAuth2AuthenticationException {
        log.info("PrincipalDetailsOauth2Service loadUser..." + userRequest);
        log.info("OAuth2 로그인 요청: {}", userRequest.getClientRegistration().getRegistrationId());


        // 1. 소셜에서 전달된 사용자 정보(attributes)
        OAuth2User oAuth2User = super.loadUser(userRequest);
        Map<String, Object> attributes = oAuth2User.getAttributes();
        log.info("oAuthuser : " + oAuth2User);
        log.info("social Attributes: {}", attributes);

        // 2. provider 구분
        String provider = userRequest.getClientRegistration().getRegistrationId();

        // 3. provider별 userInfo 객체 생성
        OAuth2UserInfo oAuth2UserInfo = null;
        if ("kakao".equals(provider)) {
            oAuth2UserInfo = new KakaoUserInfo(attributes);
        }else if ("naver".equals(provider)) {
            oAuth2UserInfo = new NaverUserInfo(attributes);
        }
        else if ("google".equals(provider)) {
            oAuth2UserInfo = new GoogleUserInfo(attributes);
        } else {
            throw new OAuth2AuthenticationException("지원하지 않는 로그인 제공자: " + provider);
        }

        // 4. DB 조회 (이미 가입한 회원인지 확인)
        String providerId = oAuth2UserInfo.getProviderId();
        String email = oAuth2UserInfo.getEmail();

        // DB 조회 (email + provider 기준)
        User user = userRepository.findByEmailAndProvider(email, provider).orElse(null);

        // 5. 없으면 회원가입 (소셜 전용)
        if (user == null) {
            log.info("신규 social 사용자 → 회원가입 진행: {}", email);
            user = User.builder()
                    .email(email)
                    .nickname(oAuth2UserInfo.getName() != null ? oAuth2UserInfo.getName() : provider + "_" + providerId) // 닉네임 없으면 providerId 기반
                    .passwordHash(passwordEncoder.encode("1234")) // 더미 비밀번호 (null 허용 안 되므로)
                    .role(User.Role.USER)
                    .isActive(true)
                    .provider(provider)
                    .providerId(providerId)
                    .build();
            log.info("신규 social 사용자 저장: {} / provider={}", email, provider);
            userRepository.save(user);
        }

        // 6. PrincipalDetails 반환 (SecurityContext에 저장됨)
        return new PrincipalDetails(user, attributes);
    }
}
