package com.example.gatewayservice.filter;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cloud.gateway.filter.GatewayFilter;
import org.springframework.cloud.gateway.filter.factory.AbstractGatewayFilterFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import javax.crypto.SecretKey;
import java.util.Base64;

// Spring Cloud Gateway의 필터로 사용하기 위한 컴포넌트
@Component
public class JwtFilter extends AbstractGatewayFilterFactory<JwtFilter.Config> {

    private static final Logger logger = LoggerFactory.getLogger(JwtFilter.class);
    private final SecretKey secretKey;

    // JWT 시크릿 키를 주입받아 초기화
    public JwtFilter(@Value("${jwt.secret}") String secret) {
        super(Config.class);
        this.secretKey = Keys.hmacShaKeyFor(Base64.getDecoder().decode(secret));
        logger.info("JwtFilter initialized with secret key");
    }

    // 실제 필터 로직을 구현하는 메소드
    @Override
    public GatewayFilter apply(Config config) {
        return (exchange, chain) -> {
            logger.info("JwtFilter is being applied");
            ServerHttpRequest request = exchange.getRequest();
            logger.debug("Request headers: {}", request.getHeaders());

            // /auth/** 경로는 JWT 검증을 건너뜀 (로그인 등의 인증 요청을 위해)
            if (request.getURI().getPath().startsWith("/auth/")) {
                logger.debug("Skipping JWT filter for /auth/** path");
                return chain.filter(exchange);
            }

            // Authorization 헤더에서 JWT 토큰 추출
            String authHeader = request.getHeaders().getFirst(HttpHeaders.AUTHORIZATION);

            if (authHeader == null || !authHeader.startsWith("Bearer ")) {
                logger.warn("Authorization header is missing or invalid.");
                return this.onError(exchange, "Missing or malformed Authorization header", HttpStatus.UNAUTHORIZED);
            }

            String token = authHeader.substring(7);
            logger.debug("Extracted token: {}", token);

            try {
                // JWT 토큰 검증 및 클레임 추출
                Claims claims = Jwts.parserBuilder()
                        .setSigningKey(secretKey)
                        .build()
                        .parseClaimsJws(token)
                        .getBody();

                // 검증된 사용자 정보를 요청 헤더에 추가
                ServerHttpRequest modifiedRequest = exchange.getRequest().mutate()
                        .header("X-Authenticated-User", claims.getSubject())
                        .build();
                logger.debug("Successfully parsed claims: {}", claims);
                logger.debug("Added X-Authenticated-User header: {}", claims.getSubject());

                // 수정된 요청으로 다음 필터 체인 실행
                return chain.filter(exchange.mutate().request(modifiedRequest).build());
            } catch (Exception e) {
                // JWT 검증 실패 시 에러 처리
                logger.error("Error while parsing token: {}, token: {}", e.getMessage(), token, e);
                return this.onError(exchange, "Invalid token: " + e.getMessage(), HttpStatus.UNAUTHORIZED);
            }
        };
    }

    // 에러 발생 시 처리 메소드
    private Mono<Void> onError(ServerWebExchange exchange, String err, HttpStatus httpStatus) {
        logger.error("Request error: {}", err);
        exchange.getResponse().setStatusCode(httpStatus);
        return exchange.getResponse().setComplete();
    }

    // 필터 설정을 위한 내부 클래스 (현재는 사용되지 않음)
    public static class Config {
        // 필요한 경우 설정 속성 추가
    }
}
