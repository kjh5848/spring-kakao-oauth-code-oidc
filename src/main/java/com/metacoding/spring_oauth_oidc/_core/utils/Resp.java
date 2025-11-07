package com.metacoding.spring_oauth_oidc._core.utils;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;

import lombok.Data;

@Data
public class Resp<T> {
    private Integer status;
    private String msg;
    private T body;

    public Resp(Integer status, String msg, T body) {
        this.status = status;
        this.msg = msg;
        this.body = body;
    }

    public static <B> ResponseEntity<Resp<B>> ok(B body) {
        return ok("성공", body);
    }

    public static <B> ResponseEntity<Resp<B>> ok(String msg, B body) {
        Resp<B> resp = new Resp<>(200, msg, body);
        return new ResponseEntity<>(resp, HttpStatus.OK);
    }


}
