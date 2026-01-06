package store.kanggyeonggu.gateway.jwt;

import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;

import java.util.UUID;

/**
 * Refresh Token 관리 서비스
 * 
 * 보안 원칙:
 * - Refresh Token은 HttpOnly 쿠키로만 저장
 * - JavaScript에서 접근 불가 (XSS 방어)
 * - Secure 플래그로 HTTPS에서만 전송 (프로덕션)
 * - SameSite로 CSRF 방어
 */
@Service
public class RefreshTokenService {

    @Value("${jwt.refresh-expiration:604800000}") // 7일 (밀리초)
    private long refreshExpiration;

    @Value("${app.cookie.secure:false}") // 로컬: false, 프로덕션: true
    private boolean cookieSecure;

    @Value("${app.cookie.domain:}") // 프로덕션: .kanggyeonggu.store
    private String cookieDomain;

    private static final String REFRESH_TOKEN_COOKIE_NAME = "refresh_token";

    /**
     * Refresh Token 생성 (UUID 기반)
     */
    public String generateRefreshToken() {
        return UUID.randomUUID().toString();
    }

    /**
     * HttpOnly 쿠키로 Refresh Token 설정
     * 
     * 로컬 개발: SameSite 생략 (cross-port 쿠키 전송 허용)
     * 프로덕션: SameSite=None + Secure (cross-origin 허용, HTTPS 필수)
     */
    public void setRefreshTokenCookie(HttpServletResponse response, String refreshToken) {
        String cookieHeader;
        
        if (cookieSecure) {
            // 프로덕션: HTTPS + SameSite=None
            if (cookieDomain != null && !cookieDomain.isEmpty()) {
                cookieHeader = String.format(
                        "%s=%s; Path=/; Max-Age=%d; HttpOnly; Secure; SameSite=None; Domain=%s",
                        REFRESH_TOKEN_COOKIE_NAME,
                        refreshToken,
                        (int) (refreshExpiration / 1000),
                        cookieDomain);
            } else {
                cookieHeader = String.format(
                        "%s=%s; Path=/; Max-Age=%d; HttpOnly; Secure; SameSite=None",
                        REFRESH_TOKEN_COOKIE_NAME,
                        refreshToken,
                        (int) (refreshExpiration / 1000));
            }
        } else {
            // 로컬 개발: SameSite 생략하여 cross-port 쿠키 전송 허용
            cookieHeader = String.format(
                    "%s=%s; Path=/; Max-Age=%d; HttpOnly",
                    REFRESH_TOKEN_COOKIE_NAME,
                    refreshToken,
                    (int) (refreshExpiration / 1000));
        }
        
        // Set-Cookie 헤더로 직접 설정 (SameSite 속성 지원)
        response.setHeader("Set-Cookie", cookieHeader);

        System.out.println("✅ Refresh Token 쿠키 설정 완료 (HttpOnly): " + 
                (cookieSecure ? "Secure + SameSite=None" : "로컬 개발 모드"));
    }

    /**
     * 쿠키에서 Refresh Token 읽기
     */
    public String getRefreshTokenFromCookie(HttpServletRequest request) {
        Cookie[] cookies = request.getCookies();
        if (cookies == null) {
            return null;
        }

        for (Cookie cookie : cookies) {
            if (REFRESH_TOKEN_COOKIE_NAME.equals(cookie.getName())) {
                return cookie.getValue();
            }
        }
        return null;
    }

    /**
     * Refresh Token 쿠키 삭제 (로그아웃 시)
     */
    public void clearRefreshTokenCookie(HttpServletResponse response) {
        Cookie cookie = new Cookie(REFRESH_TOKEN_COOKIE_NAME, null);
        cookie.setHttpOnly(true);
        cookie.setSecure(cookieSecure);
        cookie.setPath("/");
        cookie.setMaxAge(0); // 즉시 만료

        if (cookieDomain != null && !cookieDomain.isEmpty()) {
            cookie.setDomain(cookieDomain);
        }

        response.addCookie(cookie);

        System.out.println("🗑️ Refresh Token 쿠키 삭제 완료");
    }

    /**
     * Refresh Token 만료 시간 반환 (밀리초)
     */
    public long getRefreshExpiration() {
        return refreshExpiration;
    }
}
