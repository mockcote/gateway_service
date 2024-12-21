package com.example.gatewayservice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;

// Spring Security 설정을 위한 구성 클래스임을 나타냄
@Configuration
// WebFlux 환경에서 Spring Security를 활성화
@EnableWebFluxSecurity
public class SecurityConfig {

    // Spring Security의 필터 체인을 구성하는 빈 메서드
    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
                // CSRF 보호 기능을 비활성화
                .csrf(csrf -> csrf.disable())
                // 서버 측 세션을 사용하지 않도록 설정 (Stateless)
                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
                // 요청에 대한 인증/인가 규칙 설정
                .authorizeExchange(exchange -> exchange
                    // /auth/**, /user/**, /test/** 경로에 대해 모든 요청 허용
                    .pathMatchers("/auth/**", "/user/**", "/test/**").permitAll()
                    // 그 외 모든 요청도 허용 (JWT 필터에서 처리하므로)
                    .anyExchange().permitAll()
                )
                .build();
    }
}
