package com.example.springjwt.util;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.util.Optional;

// CookieUtil : JWT를 저장해주는 공간 -> 읽어들여오거나 삭제하는 작업
public class CookieUtil {
    // 쿠키 추가
    public static void addCookie(HttpServletResponse response, String name, String value, int maxAge)
    // response에 담아서 보내, name 쿠키 이름, value 토큰 값, maxAge 토큰 유효기간
    {
        Cookie cookie = new Cookie(name, value);
        cookie.setPath("/");
        cookie.setMaxAge(maxAge);
        cookie.setHttpOnly(true); // JavaScript 접근 방지
        // cookie.setSecure(true); // HTTPS에서만 전송되도록 설정 (운영 환경 권장)
        response.addCookie(cookie);
    }

    // 쿠키 조회 (가져오기)
    public static Optional<String> getCookie(HttpServletRequest request, String name)
    // 리스트를 순서대로 순회해서 내가 찾으려는 key(name)의 쿠키가 있는지 보고 있으면 return 없으면 empty로 처리
    // 없다 의 조건: 유저가 직접 지웠거나, 만료시간이 지났거나, 우리가 지웠거나
    {
        Cookie[] cookies = request.getCookies(); // request안에 getCookies가 있어
        if (cookies != null) { // 있으면 받아오고
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(name)) {
                    return Optional.of(cookie.getValue());
                    // accessToken에 있는 value 값 받아오기
                }
            }
        }
        return Optional.empty(); // 없으면 empty 처리
    }

    // 쿠키 삭제
    // 로그아웃, 쿠키의 특정한 값을 ""로 덮어버리고 경로도 루트로 바꿈
    public static void deleteCookie(HttpServletRequest request, HttpServletResponse response, String name) {
        Cookie[] cookies = request.getCookies();
        if (cookies != null) {
            for (Cookie cookie : cookies) {
                if (cookie.getName().equals(name)) { // 이름이 같다면
                    cookie.setValue(""); // 값도 비우고
                    cookie.setPath("/"); // 경로도 루트로 바꾸고
                    cookie.setMaxAge(0); // 쿠키 만료시키기
                    response.addCookie(cookie); // 빈 쿠키 넣기
                }
            }
        }
    }
}
