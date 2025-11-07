package com.metacoding.spring_oauth._core.utils;

import java.text.ParseException;
import java.util.Date;

import com.metacoding.spring_oauth.user.User;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

public class JwtUtil {

    private static final String SECRET = "metacoding-secret-key-should-be-long"; // 32바이트 이상

    // JWT 생성
    public static String create(User user) {
        try {
            // 1. 클레임 설정
            JWTClaimsSet claims = new JWTClaimsSet.Builder()
                    .subject("blog")
                    .issueTime(new Date())
                    .expirationTime(new Date(System.currentTimeMillis() + 60000 * 60)) // 1시간 유효
                    .claim("id", user.getId())
                    .claim("username", user.getUsername())
                    .build();

            // 2. JWT 서명 생성 (HS256)
            SignedJWT signedJWT = new SignedJWT(
                    new JWSHeader(JWSAlgorithm.HS256),
                    claims
            );
            signedJWT.sign(new MACSigner(SECRET));

            // 3. 문자열 형태로 반환
            return signedJWT.serialize();

        } catch (JOSEException e) {
            throw new RuntimeException("JWT 생성 실패", e);
        }
    }

    // JWT 검증 및 유저 반환
    public static User verify(String token) {
        try {
            // 1. 토큰 파싱
            SignedJWT signedJWT = SignedJWT.parse(token);

            // 2. 서명 검증
            JWSVerifier verifier = new MACVerifier(SECRET);
            if (!signedJWT.verify(verifier)) {
                throw new RuntimeException("JWT 서명 검증 실패");
            }

            // 3. 만료 확인
            JWTClaimsSet claims = signedJWT.getJWTClaimsSet();
            Date expiration = claims.getExpirationTime();
            if (new Date().after(expiration)) {
                throw new RuntimeException("JWT 만료됨");
            }

            // 4. 유저 정보 복원
            int id = claims.getIntegerClaim("id");
            String username = claims.getStringClaim("username");

            return User.builder()
                    .id(id)
                    .username(username)
                    .build();

        } catch (ParseException | JOSEException e) {
            throw new RuntimeException("JWT 검증 실패", e);
        }
    }
}