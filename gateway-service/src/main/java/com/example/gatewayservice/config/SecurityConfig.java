package com.example.gatewayservice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;

// Spring Security 설정 클래스임을 나타내는 어노테이션
@Configuration
// WebFlux 환경에서 Spring Security를 활성화하기 위한 어노테이션
@EnableWebFluxSecurity
public class SecurityConfig {

    // 허용할 URI 목록을 관리하는 AllowedUriConfig 의존성 주입
    private final AllowedUriConfig allowedUriConfig;

    // 생성자를 통해 AllowedUriConfig 주입받음 (스프링 컨테이너에서 자동으로 주입)
    public SecurityConfig(AllowedUriConfig allowedUriConfig) {
        this.allowedUriConfig = allowedUriConfig;
    }

    // Spring Security의 필터 체인을 정의하는 메서드
    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
                // CSRF 보호 기능 비활성화 (REST API 서버에서는 일반적으로 비활성화)
                .csrf(csrf -> csrf.disable())
                // Stateless 설정: 서버에서 세션을 사용하지 않도록 설정 (JWT 기반 인증에 적합)
                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance())
                
                // 요청에 대한 인증 및 인가 규칙 정의
                .authorizeExchange(exchange -> exchange
                    // 허용할 경로를 AllowedUriConfig에서 가져와서 모두 허용 처리
                    .pathMatchers(allowedUriConfig.getAllowedUris().toArray(new String[0])).permitAll()
                    
                    // 그 외 모든 요청은 막아 버림 (허용되지 않은 경로는 차단됨)
                    .anyExchange().authenticated()
                )
                
                .build();
    }
}
