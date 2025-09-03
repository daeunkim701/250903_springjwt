package com.example.springjwt.util;

import io.jsonwebtoken.security.Keys;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

import javax.crypto.SecretKey;
import java.nio.charset.StandardCharsets;

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
}
