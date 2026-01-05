package store.kanggyeonggu.gateway.userservice.config;

import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

/**
 * Spring Security 설정
 */
@Configuration
@EnableWebSecurity
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtAuthenticationFilter jwtAuthenticationFilter;

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
                .csrf(csrf -> csrf.disable())
                .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        // 공개 엔드포인트 (인증 불필요)
                        .requestMatchers(
                                "/user/health",
                                "/actuator/**",
                                "/docs/**", // Swagger UI
                                "/swagger-ui/**", // Swagger UI (대체 경로)
                                "/swagger-ui.html", // Swagger UI (구버전)
                                "/docs/api-docs/**", // OpenAPI JSON
                                "/auth/**", // OAuth 로그인 (카카오, 네이버, 구글)
                                "/oauth2/**" // OAuth 콜백
                        ).permitAll()
                        // 나머지 요청은 인증 필요
                        .anyRequest().authenticated())
                .addFilterBefore(jwtAuthenticationFilter, UsernamePasswordAuthenticationFilter.class);

        return http.build();
    }
}
