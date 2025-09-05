package com.example.demo.controller;

import com.example.demo.config.auth.PrincipalDetails;
import com.example.demo.domain.dto.UserDto;
import com.example.demo.domain.repository.UserRepository;
import com.example.demo.domain.sevice.OAuthUnlinkService;
import com.example.demo.domain.sevice.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;

@Controller
@Slf4j
@RequiredArgsConstructor
public class AuthController {

    private final UserService userService;
    private final OAuthUnlinkService oAuthUnlinkService;
    private final UserRepository userRepository;

    @GetMapping("/login")
    public String login() {
        log.info("GET/login ______ ");
        return "login";
    }

    @GetMapping("/join")
    public void joinGet() {
        log.info("GET/join ______ ");
    }

    @PostMapping("/join")
    public String joinPost(UserDto userDto) {
        log.info("POST /join: {}", userDto);

        try {
            userService.registerUser(userDto, userDto.getEmail());
        } catch (IllegalArgumentException e) {
            log.warn("회원가입 실패: {}", e.getMessage());
            // 실패 시 처리 (예: 가입 페이지로 리다이렉트 + 에러 메시지)
            return "join"; // join.html 페이지
        }

        // 성공 시 로그인 페이지 또는 홈으로 이동
        return "redirect:/login";
    }

    @DeleteMapping("/unlink")
    public String unlinkAccount(@AuthenticationPrincipal PrincipalDetails principalDetails) {
        String provider = principalDetails.getUser().getProvider();
        String accessToken = principalDetails.getAccessToken();
        String email = principalDetails.getUser().getEmail();

        if(provider != null && accessToken != null){
            switch(provider){
                case "kakao" -> oAuthUnlinkService.unlinkKakao(accessToken);
                case "naver" -> oAuthUnlinkService.unlinkNaver(accessToken,
                        "YOUR_NAVER_CLIENT_ID", "YOUR_NAVER_CLIENT_SECRET");
                case "google" -> oAuthUnlinkService.unlinkGoogle(accessToken);
                default -> throw new IllegalArgumentException("Unknown provider: " + provider);
            }

            // DB에서 사용자 정보 삭제
            userRepository.deleteByEmail(email);
        }

        return "계정 연결 해제 완료";
    }

}
