package com.example.demo.config.auth.loginHandler;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;

import java.io.IOException;
import java.util.Collection;


@Slf4j
public class CustomLoginSuccessHandler implements AuthenticationSuccessHandler {
    @Override
    public void onAuthenticationSuccess(HttpServletRequest request,
                                        HttpServletResponse response,
                                        Authentication authentication) throws IOException, ServletException {

        String path = request.getContextPath();
        log.info("로그인 성공 - authentication: {}", authentication);

        Collection<? extends GrantedAuthority> authorities = authentication.getAuthorities();

        String redirectUrl = path + "/user"; // 기본값

        for (GrantedAuthority authority : authorities) {
            String role = authority.getAuthority();
            log.info("ROLE : {}", role);

            if ("ROLE_ADMIN".equals(role)) {
                redirectUrl = path + "/admin";
                break; // ADMIN 권한이 있으면 바로 종료
            }
        }

        response.sendRedirect(redirectUrl);
    }
}
