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
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

        String path = request.getContextPath();

        log.info("CustomLoginSuccessHandler's on AuthenticationSuccess authentication : " + authentication);
        Collection<? extends GrantedAuthority> collection = authentication.getAuthorities();

        collection.forEach(role -> {
            log.info("ROLE : " + role.getAuthority());
            String role_str = role.getAuthority();

            try{
                if(role_str.equals("ROLE_ADMIN")){
                    response.sendRedirect(path + "/admin");
                    return;
                } else {
                    response.sendRedirect(path + "/user");
                    return;
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        });
    }
}
