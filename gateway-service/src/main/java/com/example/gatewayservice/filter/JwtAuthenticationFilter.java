package com.example.gatewayservice.filter;

import io.jsonwebtoken.Claims;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;

// Spring Cloud Gateway의 커스텀 필터 클래스를 정의
@Component
public class JwtAuthenticationFilter extends AbstractGatewayFilterFactory<JwtAuthenticationFilter.Config> {

    // 로깅을 위한 Logger 객체 생성
    private static final Logger logger = LoggerFactory.getLogger(JwtAuthenticationFilter.class);

    // JWT 검증을 위한 JwtProvider 의존성 주입
    private final JwtProvider jwtProvider;

    // 생성자에서 JwtProvider를 주입받음
    public JwtAuthenticationFilter(JwtProvider jwtProvider) {
        super(Config.class); // 필터의 설정 클래스를 지정
        this.jwtProvider = jwtProvider; // JwtProvider 초기화
    }

    // GatewayFilter를 적용하는 메서드
    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            logger.debug("Incoming request: {}", exchange.getRequest().getURI()); // 요청 URI 로깅

            String token = resolveToken(exchange); // **HTTP 헤더에서 JWT 추출**
            if (token != null) {
                logger.debug("Extracted token: {}", token); // 추출한 토큰 로깅

                if (jwtProvider.validateToken(token)) { // **토큰 유효성 검증**
                    logger.debug("Token is valid."); // 유효한 토큰 로깅
                    Claims claims = jwtProvider.getClaims(token); // **JWT 클레임 추출**
                    logger.debug("Extracted claims: {}", claims); // 추출한 클레임 로깅

                    // **X-Authenticated-User 헤더 추가**
                    ServerHttpRequest modifiedRequest = exchange.getRequest()
                            .mutate() // 요청을 수정하기 위한 메서드 호출
                            .header("X-Authenticated-User", claims.getSubject()) // 클레임에서 사용자 정보를 가져와 헤더에 추가
                            .build(); // 수정된 요청 객체 생성

                    logger.debug("Added X-Authenticated-User header: {}", claims.getSubject()); // 추가된 헤더 로깅

                    // **수정된 요청으로 체인 실행**
                    return chain.filter(exchange.mutate().request(modifiedRequest).build()); // 수정된 요청으로 필터 체인 실행
                } else {
                    logger.warn("Token validation failed."); // 토큰 검증 실패 로깅
                    exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED); // 401 Unauthorized 응답 설정
                    return exchange.getResponse().setComplete(); // 응답 완료
                }
            } else {
                logger.warn("No valid token found in the request."); // 유효한 토큰이 없음을 로깅
                exchange.getResponse().setStatusCode(HttpStatus.UNAUTHORIZED); // 401 Unauthorized 응답 설정
                return exchange.getResponse().setComplete(); // 응답 완료
            }
        };
    }

    // HTTP 요청에서 JWT를 추출하는 메서드
    private String resolveToken(ServerWebExchange exchange) {
        String bearerToken = exchange.getRequest().getHeaders().getFirst(HttpHeaders.AUTHORIZATION); // Authorization 헤더에서 토큰 추출
        if (bearerToken != null && bearerToken.startsWith("Bearer ")) { 
            logger.debug("Authorization header found: {}", bearerToken); // Authorization 헤더 존재 로깅
            return bearerToken.substring(7); // **"Bearer " 제거 후 토큰 반환**
        }
        logger.warn("Authorization header is missing or invalid."); // Authorization 헤더가 없거나 잘못됨을 로깅
        return null; // 유효한 토큰이 없으면 null 반환
    }

    public static class Config {
        // 여기에 필요한 설정을 추가할 수 있음 (현재는 비어 있음)
    }
}
