package com.metacoding.spring_oauth._core.utils;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import com.metacoding.spring_oauth.user.KakaoResponse;

@Component
public class KakaoToken {

    @Value("${kakao.client-id}")
    private String kakaoApiClientId;

    @Value("${kakao.redirect-uri}")
    private String kakaoApiRedirectUri;

    @Value("${kakao.client-secret:}")
    private String kakaoApiClientSecret;

    public KakaoResponse.TokenDTO getKakaoToken(String code, RestTemplate restTemplate) {
        HttpEntity<MultiValueMap<String, String>> request = createTokenRequest(code);

        ResponseEntity<KakaoResponse.TokenDTO> response = restTemplate.exchange(
                "https://kauth.kakao.com/oauth/token",
                HttpMethod.POST,
                request,
                KakaoResponse.TokenDTO.class);
        return response.getBody();
    }

    public KakaoResponse.KakaoUserDTO getKakaoUser(String accessToken, RestTemplate restTemplate) {
        HttpEntity<MultiValueMap<String, String>> request = createUserRequest(accessToken);

        ResponseEntity<KakaoResponse.KakaoUserDTO> response = restTemplate.exchange(
                "https://kapi.kakao.com/v2/user/me",
                HttpMethod.GET,
                request,
                KakaoResponse.KakaoUserDTO.class);
        return response.getBody();
    }

    private HttpEntity<MultiValueMap<String, String>> createTokenRequest(String code) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Content-Type", "application/x-www-form-urlencoded;charset=utf-8");

        MultiValueMap<String, String> body = new LinkedMultiValueMap<>();
        body.add("grant_type", "authorization_code");
        body.add("client_id", kakaoApiClientId);
        body.add("redirect_uri", kakaoApiRedirectUri);
        body.add("code", code);
        if (kakaoApiClientSecret != null && !kakaoApiClientSecret.isBlank()) {
            body.add("client_secret", kakaoApiClientSecret);
        }

        return new HttpEntity<>(body, headers);
    }

    private HttpEntity<MultiValueMap<String, String>> createUserRequest(String accessToken) {
        HttpHeaders headers = new HttpHeaders();
        headers.add("Content-Type", "application/x-www-form-urlencoded;charset=utf-8");
        headers.add("Authorization", "Bearer " + accessToken);

        return new HttpEntity<>(headers);
    }

}
