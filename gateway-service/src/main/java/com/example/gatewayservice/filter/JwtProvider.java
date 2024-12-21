package com.example.gatewayservice.filter;

import java.util.Base64; // Base64 인코딩 및 디코딩을 위한 클래스
import javax.crypto.SecretKey; // 비밀 키를 위한 클래스
import org.springframework.beans.factory.annotation.Value; // Spring의 @Value 어노테이션
import org.springframework.stereotype.Component; // Spring 컴포넌트로 등록하기 위한 어노테이션
import io.jsonwebtoken.Claims; // JWT의 클레임을 나타내는 클래스
import io.jsonwebtoken.Jwts; // JWT 관련 기능을 제공하는 클래스
import io.jsonwebtoken.security.Keys; // JWT 서명 키를 생성하는 클래스

// JWT 관련 기능을 제공하는 컴포넌트 클래스
@Component
public class JwtProvider {

    private final SecretKey key; // **미리 생성된 SecretKey 객체**

    // 생성자에서 JWT 비밀 키를 초기화
    public JwtProvider(@Value("${jwt.secret}") String secretKey) {
        this.key = Keys.hmacShaKeyFor(Base64.getDecoder().decode(secretKey));
    }

    // JWT 유효성 검증 메서드
    public boolean validateToken(String token) {
        try {
            Jwts.parserBuilder() // JWT 파서 빌더 생성
                .setSigningKey(key) // 서명 검증에 사용할 키 설정
                .build() // 파서 빌드
                .parseClaimsJws(token); // **JWT 파싱 및 서명 검증**
            return true; // 유효한 토큰인 경우 true 반환
        } catch (Exception e) {
            System.err.println("JWT validation failed: " + e.getMessage()); // 검증 실패 시 에러 메시지 출력
            return false; // **유효하지 않은 토큰 처리**
        }
    }

    // JWT에서 클레임 추출 메서드
    public Claims getClaims(String token) {
        try {
            return Jwts.parserBuilder() // JWT 파서 빌더 생성
                       .setSigningKey(key) // 서명 검증에 사용할 키 설정
                       .build() // 파서 빌드
                       .parseClaimsJws(token) // JWT 파싱
                       .getBody(); // **JWT의 Payload에서 클레임 추출**
        } catch (Exception e) {
            System.err.println("Failed to extract claims from token: " + e.getMessage()); // 클레임 추출 실패 시 에러 메시지 출력
            return null; // **비정상적인 토큰에 대한 처리**
        }
    }
}
