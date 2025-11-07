package com.metacoding.spring_oauth.user;

public class KakaoRequset {

    public record KakaoDTO(
            String code,
            String nonce) {
    }

}
