package com.metacoding.spring_oauth.user;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.Optional;
import java.util.UUID;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestTemplate;

import com.metacoding.spring_oauth._core.utils.JwtUtil;
import com.metacoding.spring_oauth._core.utils.KakaoOidcUtil;
import com.metacoding.spring_oauth._core.utils.KakaoToken;

import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;

@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
public class UserService {

    private final UserRepository userRepository;
    private final HttpSession session;
    private final KakaoToken kakaoToken;
    private final KakaoOidcUtil kakaoOidcUtil;
    private final RestTemplate restTemplate = new RestTemplate();

    @Value("${kakao.authorize-uri}")
    private String kakaoApiAuthorizeUri;

    @Value("${kakao.client-id}")
    private String kakaoApiClientId;

    @Value("${kakao.redirect-uri}")
    private String kakaoApiRedirectUri;

    /**
     * 일반 로그인 - JWT 생성 후 반환
     */
    @Transactional
    public String 로그인(UserRequest.LoginDTO reqDTO) {
        User user = userRepository.findByUsernameAndPassword(reqDTO.username(), reqDTO.password())
                .orElseThrow(() -> new RuntimeException("유효하지 않은 로그인 정보입니다."));

        // JWT 발급 (서비스 내부에서 처리)
        return JwtUtil.create(user);
    }

    /**
     * 회원가입 - 저장 후 JWT 생성
     */
    @Transactional
    public UserResponse.DTO 회원가입(UserRequest.JoinDTO reqDTO) {
        Optional<User> userOP = userRepository.findByUsername(reqDTO.username());
        if (userOP.isPresent()) {
            throw new RuntimeException("이미 사용 중인 유저네임입니다.");
        }

        User user = userRepository.save(reqDTO.toEntity());
        return new UserResponse.DTO(user);
    }

    /**
     * 카카오 로그인 URL 생성
     * https://accounts.kakao.com/login/?continue=https%3A%2F%2Fkauth.kakao.com%2Foauth%2Fauthorize%3Fresponse_type%3Dcode%26
     * client_id%3D200429b30f3909ea3fd28224cddc7b25%26
     * redirect_uri%3Dhttp%253A%252F%252Flocalhost%253A8080%252Foauth%252Fcallback%26
     * scope%3Dopenid%2520profile_nickname%26
     * nonce%3Dkakao_nonce%26through_account%3Dtrue%26auth_tran_id%3DAcdlyMNwE_KbSQnixpr7JEeXuDsX7_E-OY78AjFqCg0gWgAAAZpcVMnf#login
     * 
     */
    public String 카카오로그인주소() {

        // nonce: 1회성 검증 키, 검증하고 나면 반드시 삭제해야 한다.
        String nonce = UUID.randomUUID().toString();
        session.setAttribute("kakao_nonce", nonce); // 서버 세션에 저장

        String encodedRedirect = URLEncoder.encode(kakaoApiRedirectUri, StandardCharsets.UTF_8);
        String scope = URLEncoder.encode("openid profile_nickname", StandardCharsets.UTF_8);
        return kakaoApiAuthorizeUri
                + "?response_type=code"
                + "&client_id=" + kakaoApiClientId
                + "&redirect_uri=" + encodedRedirect
                + "&scope=" + scope
                + "&nonce=" + nonce;
    }

    /**
     * 카카오 로그인 (인가코드 방식)
     */
    @Transactional
    public String 카카오로그인(String code) {
        // 인가 코드로 토큰 요청 (access_token + id_token 포함)
        KakaoResponse.TokenDTO tokenDTO = kakaoToken.getKakaoToken(code, restTemplate);
        if (tokenDTO == null || tokenDTO.accessToken() == null) {
            throw new RuntimeException("카카오 Access Token 발급에 실패했습니다.");
        }

        // 세션에서 내가 요청 시 저장한 nonce 꺼내기
        String sessionNonce = (String) session.getAttribute("kakao_nonce");

        // OIDC 검증
        KakaoOidcResponse resDTO = kakaoOidcUtil.verify(tokenDTO.idToken(), sessionNonce);
        if (resDTO == null || resDTO.subject() == null) {
            throw new RuntimeException("카카오 OIDC id_token 검증 실패");
        }

        // 검증 완료 시 nonce 제거
        session.removeAttribute("kakao_nonce");

        User user = 카카오사용자보장(resDTO.subject(), resDTO.nickname(), null);

        return JwtUtil.create(user);

    }

    /**
     * 카카오 유저 생성/갱신
     */
    @Transactional
    public User 카카오사용자보장(String providerId, String preferredUsername, String email) {
        String resolvedEmail = (email != null && !email.isBlank())
                ? email
                : "kakao_" + providerId + "@kakao.local";
        String resolvedUsername = (preferredUsername != null && !preferredUsername.isBlank())
                ? preferredUsername
                : "kakao_" + providerId;

        return userRepository.findByProviderAndProviderId("kakao", providerId)
                .map(user -> {
                    user.updateEmail(resolvedEmail);
                    user.updateUsername(resolvedUsername);
                    return user;
                })
                .orElseGet(() -> userRepository.save(User.builder()
                        .username(resolvedUsername)
                        .password(UUID.randomUUID().toString())
                        .email(resolvedEmail)
                        .provider("kakao")
                        .providerId(providerId)
                        .build()));
    }
}