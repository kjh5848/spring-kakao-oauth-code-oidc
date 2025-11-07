package com.metacoding.spring_oauth_oidc._core.utils;

import java.text.ParseException;
import java.util.Date;

import com.metacoding.spring_oauth_oidc.user.User;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

public class JwtUtil {

    public static final String HEADER = "Authorization";
    public static final String TOKEN_PREFIX = "Bearer ";
    private static final String SECRET = "metacoding-secret-key-should-be-long"; // 32바이트 이상
    private static final long EXPIRATION_TIME = 1000L * 60 * 60 * 24 * 7; // 7일

    // JWT 생성
    public static String create(User user) {
        try {
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .subject(user.getUsername())
                    .issueTime(new Date())
                    .expirationTime(new Date(System.currentTimeMillis() + EXPIRATION_TIME))
                    .claim("id", user.getId())
                    .build();

            SignedJWT signedJWT = new SignedJWT(
                    new JWSHeader(JWSAlgorithm.HS256),
                    claims);
            signedJWT.sign(new MACSigner(SECRET));

            return TOKEN_PREFIX + signedJWT.serialize();
            
        } catch (JOSEException e) {
            throw new RuntimeException("JWT 생성 실패", e);
        }
    }

    // JWT 검증 및 유저 반환 (학습용 간단 버전)
    public static User verify(String jwt) {
        try {
            SignedJWT signedJWT = SignedJWT.parse(jwt);
            if (!signedJWT.verify(new MACVerifier(SECRET))) {
                throw new RuntimeException("JWT 서명 검증 실패");
            }

            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            Integer id = claims.getIntegerClaim("id");
            String username = claims.getSubject();

            return User.builder()
                    .id(id)
                    .username(username)
                    .build();
        } catch (ParseException | JOSEException e) {
            throw new RuntimeException("JWT 검증 실패", e);
        }
    }
}
