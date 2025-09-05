package com.example.demo.controller;

import com.example.demo.config.auth.PrincipalDetails;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
@Slf4j
@RequiredArgsConstructor
public class UserController {


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
        if (principalDetails == null) {
            // 보안상 절대 발생 안 해야 하지만, 혹시 대비
            return "redirect:/login";
        }
        model.addAttribute("nickname", principalDetails.getUser().getNickname());
        model.addAttribute("email", principalDetails.getUser().getEmail());
        return "user";
    }

    @GetMapping("/admin")
    public void admin() {
        log.info("GET /admin ______ ");
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

    }
}
