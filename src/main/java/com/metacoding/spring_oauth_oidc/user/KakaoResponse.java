package com.metacoding.spring_oauth_oidc.user;

import java.sql.Timestamp;
import java.time.Instant;

import com.fasterxml.jackson.annotation.JsonProperty;

public class KakaoResponse {

        // 사용자 정보 DTO (/v2/user/me)
        public record KakaoUserDTO(
                        Long id,
                        @JsonProperty("connected_at") Timestamp connectedAt,
                        Properties properties) {
        }

        public record Properties(
                        String nickname) {
        }

        // 토큰 응답 DTO (/oauth/token)
        public record TokenDTO(
                        @JsonProperty("token_type") String tokenType,
                        @JsonProperty("access_token") String accessToken,
                        @JsonProperty("expires_in") Long expiresIn,
                        @JsonProperty("refresh_token") String refreshToken,
                        @JsonProperty("refresh_token_expires_in") Long refreshTokenExpiresIn,
                        @JsonProperty("id_token") String idToken, // OIDC용 ID 토큰
                        String scope) {
        }

        // OIDC 페이로드 (id_token 검증 후 결과)
        public record IdTokenDTO(
                        String sub, // 카카오 고유 식별자 (OIDC subject)
                        String nickname, // 닉네임 (scope에 따라 null 가능)
                        Instant expiresAt // 만료 시각
        ) {
        }
}