package com.example.springjwt.filter;

import com.example.springjwt.util.CookieUtil;
import com.example.springjwt.util.JwtUtil;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.apache.catalina.User;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.Collection;
import java.util.Collections;
import java.util.Optional;

@RequiredArgsConstructor
public class JwtAuthorizationFilter extends OncePerRequestFilter {
    private final JwtUtil jwtUtil;

    // 모든 요청에 대해 한 번씩만 실행되는 필터 로직임 -> 너 JWT 토큰 있니?
    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain filterChain) throws ServletException, IOException {
        // request안에 header, header안에 cookie, cookie에 accessToken이 있고
        Optional<String> accessToken = CookieUtil.getCookie(request, "accessToken");
        // request : getCookie를 이용해서 accessToken 쿠키를 받아오겠다
        if (accessToken.isPresent() && jwtUtil.validateToken(accessToken.get())) {
            // 토큰에서 사용자 이름을 추출
            String username = jwtUtil.getUsernameFromToken(accessToken.get());

            UsernamePasswordAuthenticationToken authentication
                    = new UsernamePasswordAuthenticationToken(
                    username,
                    null,
                    Collections.singletonList(new SimpleGrantedAuthority(("ROLE_USER")))
            );

            SecurityContextHolder.getContext().setAuthentication(authentication);
        }
        // 다음 필터로 요청 전달
        filterChain.doFilter(request, response);
    }
}
