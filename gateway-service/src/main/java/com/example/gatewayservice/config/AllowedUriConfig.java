package com.example.gatewayservice.config;

import org.springframework.stereotype.Component;

import java.util.List;

@Component
public class AllowedUriConfig {

    // 허용할 URI 목록
    private final List<String> allowedUris = List.of(
        "/auth/**", // 인증 관련 경로
        "/user/**", // 사용자 관련 경로
        "/test/**",  // 테스트 관련 경로
        "/stats/**", // 통계 관련 경로
        "/problems/**" //문제 관련 경로
    );

    public List<String> getAllowedUris() {
        return allowedUris;
    }
}
