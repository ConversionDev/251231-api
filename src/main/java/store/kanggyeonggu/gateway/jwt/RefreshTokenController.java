package store.kanggyeonggu.gateway.jwt;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import store.kanggyeonggu.gateway.common.entity.User;
import store.kanggyeonggu.gateway.common.repository.UserRepository;

import java.util.Map;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

/**
 * Refresh Token 관련 API 컨트롤러
 * 
 * 엔드포인트:
 * - POST /api/auth/refresh : Access Token 갱신
 * - POST /api/auth/logout : 로그아웃 (Refresh Token 삭제)
 */
@RestController
@RequestMapping("/api/auth")
public class RefreshTokenController {

    private final RefreshTokenService refreshTokenService;
    private final JwtService jwtService;
    private final RedisTemplate<String, String> redisTemplate;
    private final UserRepository userRepository;

    private static final String REFRESH_TOKEN_PREFIX = "refresh_token:";

    public RefreshTokenController(
            RefreshTokenService refreshTokenService,
            JwtService jwtService,
            RedisTemplate<String, String> redisTemplate,
            UserRepository userRepository) {
        this.refreshTokenService = refreshTokenService;
        this.jwtService = jwtService;
        this.redisTemplate = redisTemplate;
        this.userRepository = userRepository;
    }

    /**
     * Access Token 갱신
     * 
     * HttpOnly 쿠키에서 Refresh Token을 읽어 검증 후 새 Access Token 발급
     * 
     * POST /api/auth/refresh
     * Cookie: refresh_token=xxx (자동 전송)
     * 
     * Response:
     * {
     * "success": true,
     * "accessToken": "eyJ..."
     * }
     */
    @PostMapping("/refresh")
    public ResponseEntity<?> refreshToken(
            HttpServletRequest request,
            HttpServletResponse response) {
        try {
            // 1. 쿠키에서 Refresh Token 읽기
            String refreshToken = refreshTokenService.getRefreshTokenFromCookie(request);

            if (refreshToken == null || refreshToken.isEmpty()) {
                System.out.println("❌ Refresh Token 쿠키 없음");
                return ResponseEntity.status(401).body(Map.of(
                        "success", false,
                        "message", "Refresh token not found"));
            }

            System.out.println(
                    "🔍 Refresh Token 확인: " + refreshToken.substring(0, Math.min(8, refreshToken.length())) + "...");

            // 2. Redis에서 Refresh Token 검증 및 userId 조회
            String redisKey = REFRESH_TOKEN_PREFIX + refreshToken;
            String userIdStr = redisTemplate.opsForValue().get(redisKey);

            if (userIdStr == null) {
                System.out.println("❌ Refresh Token이 Redis에 없음 (만료 또는 무효)");
                refreshTokenService.clearRefreshTokenCookie(response);
                return ResponseEntity.status(401).body(Map.of(
                        "success", false,
                        "message", "Invalid or expired refresh token"));
            }

            Long userId = Long.parseLong(userIdStr);
            System.out.println("✅ Refresh Token 검증 성공, userId: " + userId);

            // 3. 사용자 정보 조회
            Optional<User> userOptional = userRepository.findById(userId);
            if (userOptional.isEmpty()) {
                System.out.println("❌ 사용자를 찾을 수 없음: " + userId);
                refreshTokenService.clearRefreshTokenCookie(response);
                return ResponseEntity.status(401).body(Map.of(
                        "success", false,
                        "message", "User not found"));
            }

            User user = userOptional.get();

            // 4. 새 Access Token 발급
            String newAccessToken = jwtService.generateToken(user.getId(), user.getNickname());
            System.out.println("✅ 새 Access Token 발급 완료");

            // 5. (선택) Refresh Token 갱신 (Rotation)
            // 보안 강화를 위해 기존 Refresh Token 삭제 후 새로 발급
            redisTemplate.delete(redisKey);

            String newRefreshToken = refreshTokenService.generateRefreshToken();
            String newRedisKey = REFRESH_TOKEN_PREFIX + newRefreshToken;
            redisTemplate.opsForValue().set(
                    newRedisKey,
                    userId.toString(),
                    refreshTokenService.getRefreshExpiration(),
                    TimeUnit.MILLISECONDS);

            refreshTokenService.setRefreshTokenCookie(response, newRefreshToken);
            System.out.println("✅ 새 Refresh Token 발급 및 쿠키 설정 완료");

            // 6. 응답
            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "accessToken", newAccessToken));

        } catch (NumberFormatException e) {
            System.err.println("❌ userId 파싱 오류: " + e.getMessage());
            return ResponseEntity.status(401).body(Map.of(
                    "success", false,
                    "message", "Invalid refresh token data"));
        } catch (Exception e) {
            System.err.println("❌ Token refresh 오류: " + e.getMessage());
            e.printStackTrace();
            return ResponseEntity.status(500).body(Map.of(
                    "success", false,
                    "message", "Token refresh failed"));
        }
    }

    /**
     * 로그아웃
     * 
     * Refresh Token 쿠키 삭제 및 Redis에서 토큰 무효화
     * 
     * POST /api/auth/logout
     */
    @PostMapping("/logout")
    public ResponseEntity<?> logout(
            HttpServletRequest request,
            HttpServletResponse response) {
        try {
            // 1. 쿠키에서 Refresh Token 읽기
            String refreshToken = refreshTokenService.getRefreshTokenFromCookie(request);

            if (refreshToken != null && !refreshToken.isEmpty()) {
                // 2. Redis에서 Refresh Token 삭제
                String redisKey = REFRESH_TOKEN_PREFIX + refreshToken;
                Boolean deleted = redisTemplate.delete(redisKey);
                System.out.println("🗑️ Redis에서 Refresh Token 삭제: " + (deleted != null && deleted));
            }

            // 3. 쿠키 삭제
            refreshTokenService.clearRefreshTokenCookie(response);

            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "message", "로그아웃 성공"));

        } catch (Exception e) {
            System.err.println("❌ 로그아웃 오류: " + e.getMessage());
            e.printStackTrace();

            // 오류가 발생해도 쿠키는 삭제
            refreshTokenService.clearRefreshTokenCookie(response);

            return ResponseEntity.ok(Map.of(
                    "success", true,
                    "message", "로그아웃 완료"));
        }
    }
}
