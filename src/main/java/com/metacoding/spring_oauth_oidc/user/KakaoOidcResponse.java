package com.metacoding.spring_oauth_oidc.user;

import java.time.Instant;

public record KakaoOidcResponse(
        String subject,
        String nickname,
        String nonce,
        Instant expiresAt) {

}
