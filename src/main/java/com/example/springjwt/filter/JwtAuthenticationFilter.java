package com.example.springjwt.filter;


import com.example.springjwt.util.CookieUtil;
import com.example.springjwt.util.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.apache.catalina.User;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import java.io.IOException;

@RequiredArgsConstructor
public class JwtAuthenticationFilter extends UsernamePasswordAuthenticationFilter {

    private final JwtUtil jwtUtil;
    private final AuthenticationManager authenticationManager;

    // login시 인증을 시도하는 메서드
    @Override // att만 치고 tab 하니까 그냥 뿅 나옴
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response) throws AuthenticationException {
        // obtainUsername, obtainPassword
        // 폼을 통해 받을 예정
        String username = obtainUsername(request);
        String password = obtainPassword(request);

        // Spring Security의 인증 토큰 생성
        UsernamePasswordAuthenticationToken authToken = new UsernamePasswordAuthenticationToken(username, password, null);

        // AuthenticationManager에 인증 위임
        return authenticationManager.authenticate(authToken);
    }

    @Override
    protected void unsuccessfulAuthentication(HttpServletRequest request, HttpServletResponse response, AuthenticationException failed) throws IOException, ServletException {
        response.sendRedirect("/login?error=true");
    }

    @Override
    protected void successfulAuthentication(HttpServletRequest request, HttpServletResponse response, FilterChain chain, Authentication authResult) throws IOException, ServletException {
        // Authorization -> User 객체 (인증의 결과로)
        User user = (User) authResult.getPrincipal();
        // 이 정보로 JWT 토큰을 생성해 (생성 로직은 jwtUtil에서 만들어)
        String accessToken = jwtUtil.createAccessToken(user.getUsername());
        // 쿠키에 AccessToken을 저장해
        long accessTokenExpiration = jwtUtil.getAccessTokenExpiration();
        CookieUtil.addCookie(response, "accessToken", accessToken, (int)(accessTokenExpiration / 1000));
        // 메인 페이지로 리다이렉트
        response.sendRedirect("/");
    }
}
