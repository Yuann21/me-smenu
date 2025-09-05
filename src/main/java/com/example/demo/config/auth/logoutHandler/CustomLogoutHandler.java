package com.example.demo.config.auth.logoutHandler;


import com.example.demo.config.auth.PrincipalDetails;
import com.example.demo.domain.sevice.OAuthUnlinkService;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.authentication.logout.LogoutHandler;
import org.springframework.security.web.authentication.rememberme.PersistentTokenRepository;

@Slf4j
public class CustomLogoutHandler implements LogoutHandler {

//    private final JwtTokenProvider jwtTokenProvider;
    private final OAuthUnlinkService oAuthUnlinkService;
    private final PersistentTokenRepository persistentTokenRepository;
    private final String naverClientId;
    private final String naverClientSecret;


    public CustomLogoutHandler(OAuthUnlinkService oAuthUnlinkService, PersistentTokenRepository persistentTokenRepository, String naverClientId, String naverClientSecret) {
        this.oAuthUnlinkService = oAuthUnlinkService;
        this.persistentTokenRepository = persistentTokenRepository;
        this.naverClientId = naverClientId;
        this.naverClientSecret = naverClientSecret;
    }


    @Override
    public void logout(HttpServletRequest request, HttpServletResponse response, Authentication authentication) {

        System.out.println("CustomLogoutHandler's logout() ----- ");


        // 세션 무효화
        HttpSession session = request.getSession(false);
        if(session != null) session.invalidate();

//        // JWT 토큰 가져오기 (쿠키에서)
//        String token = null;
//        if(request.getCookies() != null) {
//            for(Cookie c : request.getCookies()) {
//                if(c.getName().equals(JwtProperties.COOKIE_NAME)) {
//                    token = c.getValue();
//                    break;
//                }
//            }
//        }

//        if(token != null) {
//            authentication = jwtTokenProvider.getAuthentication(token);
//        }

        // PrincipalDetails 추출
        PrincipalDetails principalDetails = (PrincipalDetails) authentication.getPrincipal();
        String provider = principalDetails.getUser().getProvider();
        String accessToken = principalDetails.getAccessToken();

        // Remember-me 토큰 삭제
        persistentTokenRepository.removeUserTokens(principalDetails.getUser().getEmail());

        // OAuth 로그아웃 호출 (계정 연결 해제 아님)
        if(provider != null && accessToken != null){
            switch(provider){
                case "kakao" -> oAuthUnlinkService.logoutKakao(accessToken);
                case "naver" -> oAuthUnlinkService.logoutNaver(accessToken, naverClientId, naverClientSecret);
                case "google" -> oAuthUnlinkService.logoutGoogle(accessToken);
                default -> log.warn("알 수 없는 provider: {}", provider);
            }
        }
    }
}
