package com.example.demo.domain.sevice;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

@Service
@RequiredArgsConstructor
@Slf4j
@Component
public class OAuthUnlinkService {

    @Value("${NAVER_CLIENT_ID}")
    private String naverClientId;

    @Value("${NAVER_CLIENT_SECRET}")
    private String naverClientSecret;


    private final RestTemplate restTemplate = new RestTemplate();

    /** ------------------ 연결 해제(unlink) ------------------ */
    public void unlinkKakao(String accessToken) {
        String url = "https://kapi.kakao.com/v1/user/unlink";
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + accessToken);
        HttpEntity<Void> entity = new HttpEntity<>(headers);

        try {
            restTemplate.exchange(url, HttpMethod.POST, entity, String.class);
            log.info("카카오 계정 연결 끊기 성공");
        } catch (Exception e) {
            log.error("카카오 unlink 실패: {}", e.getMessage());
        }
    }

    public void unlinkNaver(String accessToken, String naverClientId, String naverClientSecret) {
        String url = "https://nid.naver.com/oauth2.0/token?grant_type=delete" +
                "&client_id=" + naverClientId +
                "&client_secret=" + naverClientSecret +
                "&access_token=" + accessToken +
                "&service_provider=NAVER";
        try {
            restTemplate.postForEntity(url, null, String.class);
            log.info("네이버 계정 연결 끊기 성공");
        } catch (Exception e) {
            log.error("네이버 unlink 실패: {}", e.getMessage());
        }
    }

    public void unlinkGoogle(String accessToken) {
        String url = "https://oauth2.googleapis.com/revoke?token=" + accessToken;
        try {
            restTemplate.postForEntity(url, null, String.class);
            log.info("구글 계정 연결 끊기 성공");
        } catch (Exception e) {
            log.error("구글 unlink 실패: {}", e.getMessage());
        }
    }

    /** ------------------ 로그아웃(logout) ------------------ */
    public void logoutKakao(String accessToken) {
        String url = "https://kapi.kakao.com/v1/user/logout";
        HttpHeaders headers = new HttpHeaders();
        headers.add("Authorization", "Bearer " + accessToken);
        HttpEntity<Void> entity = new HttpEntity<>(headers);

        try {
            restTemplate.exchange(url, HttpMethod.POST, entity, String.class);
            log.info("카카오 로그아웃 성공");
        } catch (Exception e) {
            log.error("카카오 로그아웃 실패: {}", e.getMessage());
        }
    }

    public void logoutNaver(String accessToken, String naverClientId, String naverClientSecret) {
        // Naver는 연결 해제 API로만 세션 만료 가능, logout용 별도 API 없음
        String url = "https://nid.naver.com/oauth2.0/token?grant_type=delete" +
                "&client_id=" + naverClientId +
                "&client_secret=" + naverClientSecret +
                "&access_token=" + accessToken +
                "&service_provider=NAVER";
        try {
            restTemplate.postForEntity(url, null, String.class);
            log.info("네이버 로그아웃 호출 성공");
        } catch (Exception e) {
            log.error("네이버 로그아웃 실패: {}", e.getMessage());
        }
    }

    public void logoutGoogle(String accessToken) {
        String url = "https://accounts.google.com/o/oauth2/revoke?token=" + accessToken;
        try {
            restTemplate.postForEntity(url, null, String.class);
            log.info("구글 로그아웃 성공");
        } catch (Exception e) {
            log.error("구글 로그아웃 실패: {}", e.getMessage());
        }
    }
}
