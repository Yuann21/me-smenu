package com.example.demo.config.auth.provider;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.Map;

@Data
@AllArgsConstructor
@NoArgsConstructor
public class NaverUserInfo implements OAuth2UserInfo{

    private String id;
    private Map<String, Object> attributes;

    public NaverUserInfo(Map<String, Object> attributes) {
        this.attributes = attributes;
        // 네이버는 response 안에 유저 정보가 있음
        Map<String, Object> response = (Map<String, Object>) attributes.get("response");
        this.id = response.get("id").toString();
    }

    @Override
    public String getName() {
        Map<String, Object> response = (Map<String, Object>) attributes.get("response");
        return (String) response.get("nickname"); // name 또는 nickname 중 원하는 값
    }

    @Override
    public String getEmail() {
        Map<String, Object> response = (Map<String, Object>) attributes.get("response");
        return (String) response.get("email");
    }

    @Override
    public String getProvider() {
        return "naver";
    }

    @Override
    public String getProviderId() {
        return this.id;
    }

    @Override
    public Map<String, Object> getAttributes() {
        return this.attributes;
    }
}
