package com.example.gatewayservice.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.context.NoOpServerSecurityContextRepository;

@Configuration
@EnableWebFluxSecurity
public class SecurityConfig {

    private final AllowedUriConfig allowedUriConfig;

    public SecurityConfig(AllowedUriConfig allowedUriConfig) {
        this.allowedUriConfig = allowedUriConfig;
    }

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(ServerHttpSecurity http) {
        return http
                .csrf(ServerHttpSecurity.CsrfSpec::disable) // CSRF 보호 비활성화
                .cors(cors -> cors.configurationSource(request -> {
                    org.springframework.web.cors.CorsConfiguration config = new org.springframework.web.cors.CorsConfiguration();
                    config.addAllowedOrigin("https://mockcote.site"); // 명시적인 도메인 허용
                    config.addAllowedOrigin("https://*.mockcote.site");
                    config.addAllowedMethod("*"); // 모든 HTTP 메서드 허용
                    config.addAllowedHeader("*"); // 모든 헤더 허용
                    config.setAllowCredentials(true); // 쿠키 허용
                    return config;
                }))
                .securityContextRepository(NoOpServerSecurityContextRepository.getInstance()) // Stateless 설정
                .authorizeExchange(exchange -> exchange
                    .pathMatchers(allowedUriConfig.getAllowedUris().toArray(new String[0])).permitAll() // 허용 URI
                    .anyExchange().authenticated() // 나머지 요청 인증 필요
                )
                .build();
    }
}
