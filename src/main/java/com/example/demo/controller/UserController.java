package com.example.demo.controller;

import com.example.demo.config.auth.PrincipalDetails;
import com.example.demo.domain.dto.UserDto;
import com.example.demo.domain.sevice.UserService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.ResponseBody;

@Controller
@Slf4j
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;


    @GetMapping("/")
    public String home(@AuthenticationPrincipal PrincipalDetails principalDetails, Model model) {
        log.info("GET/");
        if (principalDetails != null) {
            model.addAttribute("nickname", principalDetails.getUser().getNickname());
        }
        return "index";
    }

    @GetMapping("/user")
    public String user(@AuthenticationPrincipal PrincipalDetails principalDetails, Model model) {
        log.info("GET/user ______");
        model.addAttribute("nickname", principalDetails.getUser().getNickname());
        model.addAttribute("email", principalDetails.getUser().getEmail());
        return "user";
    }

    @GetMapping("/admin")
    public void admin() {
        log.info("GET /admin ______ ");
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

    }

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
            userService.registerUser(userDto);
        } catch (IllegalArgumentException e) {
            log.warn("회원가입 실패: {}", e.getMessage());
            // 실패 시 처리 (예: 가입 페이지로 리다이렉트 + 에러 메시지)
            return "join"; // join.html 페이지
        }

        // 성공 시 로그인 페이지 또는 홈으로 이동
        return "redirect:/login";
    }


    // 테스트용 비밀번호 확인
    @GetMapping("/testCheckPassword")
    @ResponseBody
    public String testCheckPassword(String email, String password) {
        if (email == null || email.isEmpty()) {
            return "Error: email is required";
        }
        boolean result = userService.checkPassword(password, email);
        return "Password matches? " + result;
    }
}
