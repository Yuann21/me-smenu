package com.example.demo.config.auth.logoutHandler;

import com.example.demo.config.auth.PrincipalDetails;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Slf4j
@Component
public class CustomLogoutSuccessHandler implements LogoutSuccessHandler {
    
    @Value("${KAKAO_CLIENT_ID}")
    private String kakaoClientId;

    @Value("${spring.security.oauth2.client.registration.kakao.redirect-uri}")
    private String kakaoLogoutRedirectUri;

    @Override
    public void onLogoutSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {

            log.info("CustomLogoutSucceessHandler's onLogoutSuccesss()");
            log.info("kakaoClientId : " + kakaoClientId );
            log.info("kakaoLogoutRedirectUri : " + kakaoLogoutRedirectUri );


            // Authentication null check
            if (authentication == null || !(authentication.getPrincipal() instanceof PrincipalDetails)) {
                log.warn("Invalid authentication, redirecting to home");
                response.sendRedirect("/");
                return;
            }

            PrincipalDetails principalDetails = (PrincipalDetails)authentication.getPrincipal();
            String provider = principalDetails.getUser().getProvider();
            log.info("Logout requested. Provider: {}", provider);


            // logout 처리
            if("kakao".equalsIgnoreCase(provider)){             // 대소문자 구분이 필요 없이. provider가 null일 때도 false만 반환되고, 예외는 안 터집
                log.info("GET /kakao/logoutWithKakao...");
                response.sendRedirect("https://kauth.kakao.com/oauth/logout?client_id="+ kakaoClientId +"&logout_redirect_uri=" + kakaoLogoutRedirectUri);
                return;
            }else if("naver".equalsIgnoreCase(provider)) {
                response.sendRedirect("https://nid.naver.com/nidlogin.logout?returl=https://www.naver.com/");
                return;
            }else if("google".equalsIgnoreCase(provider)){
                // google
                response.sendRedirect("https://accounts.google.com/Logout");
                return;
            }

        // 기본 fallback
        response.sendRedirect("/");
    }
}
