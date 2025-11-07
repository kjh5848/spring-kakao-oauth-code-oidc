package com.metacoding.spring_oauth.user;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.metacoding.spring_oauth._core.utils.ApiUtil;

import jakarta.servlet.http.HttpSession;
import lombok.RequiredArgsConstructor;

@Controller
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;
    private final HttpSession session;

    // 일반 로그인 (JWT 발급 + 헤더 반환)
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody UserRequest.LoginDTO loginDTO) {
        System.err.println("loginDTO : " + loginDTO);
        String jwt = userService.로그인(loginDTO);
        return ResponseEntity.ok()
                .header("Authorization", "Bearer " + jwt)
                .body(new ApiUtil<>("로그인 성공"));
    }

    // 회원가입
    @PostMapping("/join")
    @ResponseBody
    public ResponseEntity<?> join(@RequestBody UserRequest.JoinDTO joinDTO) {
        UserResponse.DTO resDTO = userService.회원가입(joinDTO);
        return ResponseEntity.ok(new ApiUtil<>(resDTO));
    }

    // 카카오 로그인 리다이렉트
    @GetMapping("/login/kakao")
    public String redirectToKakao() {
        return "redirect:" + userService.카카오로그인주소();
    }

    // 카카오 로그인 콜백 (JWT 발급)
    @GetMapping("/oauth/callback")
    @ResponseBody
    public ResponseEntity<?> kakaoCallback(@RequestParam(value = "code", required = false) String code) {
        if (code == null || code.isBlank()) {
            return ResponseEntity.badRequest().body(new ApiUtil<>(400, "인가 코드가 없습니다."));
        }

        String jwt = userService.카카오로그인(code);

        return ResponseEntity.ok()
                .header("Authorization", "Bearer " + jwt)
                .body(new ApiUtil<>("카카오 로그인 성공"));
    }

    @GetMapping("/logout")
    @ResponseBody
    public ResponseEntity<?> logout() {
        // 세션에 있는 nonce 삭제 
        session.invalidate();
        return ResponseEntity.ok(new ApiUtil<>(null));
    }
}