package com.metacoding.spring_oauth_oidc.user;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import com.metacoding.spring_oauth_oidc._core.utils.Resp;

import lombok.RequiredArgsConstructor;

@Controller
@RequiredArgsConstructor
public class UserController {

    private final UserService userService;

    // 일반 로그인 (JWT 발급 + 헤더 반환)
    @PostMapping("/login")
    public ResponseEntity<?> login(@RequestBody UserRequest.LoginDTO loginDTO) {
        var resDTO = userService.로그인(loginDTO);
        return Resp.ok("로그인 성공", resDTO);
    }

    // 회원가입
    @PostMapping("/join")
    @ResponseBody
    public ResponseEntity<?> join(@RequestBody UserRequest.JoinDTO joinDTO) {
        var resDTO = userService.회원가입(joinDTO);
        return Resp.ok("회원가입 성공", resDTO);
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
            return ResponseEntity.badRequest().body(new Resp<>(400, "인가 코드가 없습니다.", null));
        }
        var resDTO = userService.카카오로그인(code);
        return Resp.ok("카카오 로그인 성공", resDTO);
    }

    @GetMapping("/logout")
    @ResponseBody
    public ResponseEntity<?> logout() {
        return Resp.ok("로그아웃 성공", null);
    }
}
