package com.example.springjwt.util;

import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;
import java.util.Date;

@Component // Scan해서 등록해주겠다는 의미 (의존성을 주입하기 위해 적은 것)
public class JwtUtil {
    private final SecretKey secretKey; // 비밀키 -> JWT 토큰을 만들 때 해석할 때 쓰일 암호화 키
    private final Long accessTokenExpiration; // 만료시간 (얼마나 유지시킬 것이냐)
    // 의존성 주입 방법 : 생성자 주입, 필드 주입, 세터 주입 - 요즘은 생성자 주입이 대세
    // 순환 참조 문제 때문에 생성자 주입을 주로 쓴대

    // 생성자 주입
    // application.properties 또는 yml에 있는 값을 불러오는 것!!
    public JwtUtil(@Value("${jwt.secret}") String secret, @Value("${jwt.access-token-expiration}") Long accessTokenExpiration) {
        System.out.println("secret : " + secret);
        System.out.println("accessTokenExpiration : " + accessTokenExpiration);
        this.secretKey = Keys.hmacShaKeyFor(secret.getBytes(StandardCharsets.UTF_8));
        this.accessTokenExpiration = accessTokenExpiration;
    }

    public String createAccessToken(String username) {
        return createToken(username, accessTokenExpiration);
    }

    public long getAccessTokenExpiration() {
        return accessTokenExpiration;
    }

    private String createToken(String username, Long expiration) {
        // 토큰을 만들 때는 만료일, 변환 로직
        Date now = new Date(); // 어차피 이걸 long -> 어떤 시간대에 있든 실질적으로는 UTC
        Date expiryDate = new Date(now.getTime() + expiration);

        return Jwts.builder()
                .subject(username) // 주요내용(유저이름)
                .issuedAt(now) // 발급일시
                .expiration(expiryDate) // 만료일시
                .signWith(secretKey) // 서명에 사용할 비밀키
                .compact(); // JWT 문자열 생성
    }

    // 토큰에서 사용자 이름 추출
    public String getUsernameFromToken(String token) {
        return getClaims(token).getSubject(); // subject -> username
    }

    // 토큰 유효성 검증
    public boolean validateToken(String token) {
        try {
            // 토큰 파싱 시 예외가 발생하지 않으면 유효한 토큰
            getClaims(token);
            return true;
        } catch (Exception e) {
            // 서명 불일치, 만료 등 모든 예외를 포함
            return false;
        }
    }

    public Claims getClaims(String token) {
        return Jwts.parser()
                .verifyWith(secretKey)
                .build()
                .parseSignedClaims(token) // token은 secretKey를 사용해서 sign claim을 하는 것
                .getPayload(); // payload -> data
        // subject -> username
        // 발행일시, 만료일시...
    }

}
