package com.example.springjwt.config;

import com.example.springjwt.util.JwtUtil;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {
    private final JwtUtil jwtUtil;
    private final AuthenticationConfiguration authenticationConfiguration;
    // 의존성 주입 -> 생성자 주입 -> @RequiredArgsConstructor

    @Bean
    public PasswordEncoder passwordEncoder() { // 지금 하는 게 DB에 저장하는 게 아니기 때문에 약식으로 PasswordEncoder만 하겠대
        return new BCryptPasswordEncoder();
    }

    // SecurityFilterChain 설정
    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        // 1. CSRF(Cross-Site-Request-Forgery -> 다른 페이지에서 폼 등의 방식으로 post 등의 주요 요청을 보내는 공격 (사용자를 사칭해서 웹 사이트에 원하지 않는 명령을 보내는 공격))
        // CSRF 보호 비활성화하기 (JWT 사용 시 일반적으로 비활성화)
        // Spring Security는 Thymeleaf 등과 사용을 하면 CSRF 토큰이라는 걸 기본적인 걸로 채택
        // -> token할 때는 굳이 csrf가 필요가 없음
        // http.csrf(csrf -> scrf.disable());
        http.csrf(AbstractHttpConfigurer::disable);

        // 2. 세션 관리를 STATELESS로 설정 (세션을 사용하지 않음)
        // 토큰의 특징 : stateless (상태 없음) (세션을 stateless로 한다는 건 토큰 검증 모드로 바꾸겠다는 의미)
        http.sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS));

        // 3. 폼 로그인 방식 비활성화
        http.formLogin(AbstractHttpConfigurer::disable);

        // 4. HTTP Basic 인증 방식 비활성화
        http.httpBasic(AbstractHttpConfigurer::disable);

        // 5. URL별 접근 권한 설정
        http.authorizeHttpRequests(auth -> auth
                .requestMatchers("/login", "/css/**", "/js/**").permitAll() // 로그인 페이지 및 정적 리소스는 모두 허용
                .anyRequest().authenticated() // 그 외 모든 요청은 인증 필요
        );

        // 6. 로그아웃 설정
        http.logout(logout -> logout
                .logoutUrl("/logout") // 로그아웃 처리 URL
                .logoutSuccessHandler((request, response, authentication) -> {
                    // 쿠키 삭제 로직
                    CookieUtil.deleteCookie(request, response, "accessToken");
                    response.sendRedirect("/login");
                })
        );


        // 7. JWT 필터 등록
        // JwtAuthenticationFilter를 UsernamePasswordAuthenticationFilter 자리에 등록
        JwtAuthenticationFilter jwtAuthenticationFilter = new JwtAuthenticationFilter(authenticationManager(authenticationConfiguration), jwtUtil);
        jwtAuthenticationFilter.setFilterProcessesUrl("/login"); // 로그인 처리 URL 재정의

        http.addFilterAt(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);
        // JwtAuthorizationFilter를 BasicAuthenticationFilter 앞에 등록
        http.addFilterBefore(new JwtAuthorizationFilter(jwtUtil), UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }


}
