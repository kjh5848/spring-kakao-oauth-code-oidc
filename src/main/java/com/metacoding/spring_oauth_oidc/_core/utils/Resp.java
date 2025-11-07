package com.metacoding.spring_oauth_oidc._core.utils;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import lombok.Data;

@Data
public class Resp<T> {
    private Integer status;
    private String msg;
    private T body;
    private String token;

    public Resp(Integer status, String msg, T body) {
        this(status, msg, body, null);
    }

    public Resp(Integer status, String msg, T body, String token) {
        this.status = status;
        this.msg = msg;
        this.body = body;
        this.token = token;
    }

    public static <B> ResponseEntity<Resp<B>> ok(B body, String token) {
        Resp<B> resp = new Resp<>(200, "성공", body, token);
        return new ResponseEntity<>(resp, HttpStatus.OK);
    }


}
