package com.dialog.security;

import static org.springframework.security.config.Customizer.withDefaults;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.client.web.OAuth2AuthorizationRequestResolver;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;

import com.dialog.global.utill.CookieUtil;
import com.dialog.security.jwt.JwtAuthenticationFilter;
import com.dialog.security.jwt.JwtTokenProvider;
import com.dialog.security.oauth2.HttpCookieOAuth2AuthorizationRequestRepository;
import com.dialog.security.oauth2.OAuth2AuthenticationFailurHandler;
import com.dialog.security.oauth2.OAuth2AuthenticationSuccessHandler;
import com.dialog.user.service.CustomOAuth2UserService;

import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.web.cors.CorsConfiguration;
import org.springframework.web.cors.CorsConfigurationSource;
import org.springframework.web.cors.UrlBasedCorsConfigurationSource;
import java.util.Arrays;
import java.util.List;

@Slf4j
@RequiredArgsConstructor
@Configuration
public class SecurityConfig {

    private final MeetAuthenticationFaliureHandler faliureHandler;              // 폼 로그인 실패 시 처리기
    private final MeetAuthenticationSuccessHandler successHandler;              // 폼 로그인 성공 시 처리기
    private final OAuth2AuthenticationFailurHandler oAuth2faliureHandler;        // OAuth2 로그인 실패 핸들러
    private final OAuth2AuthenticationSuccessHandler oAuth2successHandler;      // OAuth2 로그인 성공 핸들러 JWT
    private final CustomOAuth2UserService customOAuth2UserService;               // OAuth2UserService 커스텀 구현체
    private final JwtTokenProvider jwtTokenProvider;                             // JWT 토큰 생성/검증기
    private final OAuth2AuthorizationRequestResolver customAuthorizationRequestResolver;
    private final CookieUtil cookieUtil;
    private final HttpCookieOAuth2AuthorizationRequestRepository httpCookieOAuth2AuthorizationRequestRepository;

    @Value("${app.oauth2.fail-uri}")
    String failUrl;
    
    @Bean
    public SecurityFilterChain meetFilterChain(HttpSecurity http) throws Exception {
        return http
          .cors(withDefaults()) // CORS 허용   
            // 1. CSRF 설정: 특정 경로(h2-console, /api/**)는 CSRF 보호 안함
            .csrf(csrf -> csrf.ignoringRequestMatchers("/api/**"))
            
            // 2. HTTP Basic 인증 비활성화
            .httpBasic(httpBasic -> httpBasic.disable())
            
            // 3. iframe 정책: 동일 출처만 허용 (h2-console 사용 위해)
            .headers(headers -> headers.frameOptions().sameOrigin())
            
            // 4. 세션 설정: JWT 사용 시세션 무상태(stateless)
            .sessionManagement(session -> session
                .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
            )
            
            // 5. 권한 설정: 지정된 URL만 무인증 접근 가능, 기타는 인증 필요
           .authorizeHttpRequests(auth -> auth
    		   .requestMatchers("/api/auth/signup", "/api/auth/login", "/api/auth/me", "/api/reissue", 
    				   "/api/auth/forgotPassword", "/api/auth/resetPassword").permitAll()
    		   // 추후 스프링 내부에서 css, js, images 사용시 주석 해제후 사용
//    		   .requestMatchers("/css/**",
//    				   "/js/**", "/images/**").permitAll()
               .requestMatchers("/api/admin/**").hasRole("ADMIN")
               .requestMatchers("/public/**").permitAll() // 공개 API
               .anyRequest().authenticated()  // 나머지 요청은 인증 필요
           )
            // 6. 폼 로그인 비활성화 (JWT 비사용 시 활성화 가능하여 주석 처리)
            .formLogin(formLogin -> formLogin.disable())
            
            // 7. OAuth2 로그인 설정: 커스텀 서비스 및 성공/실패 핸들러 설정
            .oauth2Login(oauth2 -> oauth2
                   .userInfoEndpoint(userInfo -> userInfo
                       .userService(customOAuth2UserService)
                   )
                   .authorizationEndpoint(authz -> authz
                       .authorizationRequestResolver(customAuthorizationRequestResolver) 
                       .authorizationRequestRepository(httpCookieOAuth2AuthorizationRequestRepository)
                   )
                   .successHandler(oAuth2successHandler)
                   .failureHandler(oAuth2faliureHandler)
               )
            
            // 8. 로그아웃 비활성화 (필요시 활성화 가능)
            .logout(logout -> logout.disable())
            
            // 9. JWT 필터 등록: 폼 로그인 전에 실행되도록 함
            .addFilterBefore(new JwtAuthenticationFilter(jwtTokenProvider, cookieUtil), UsernamePasswordAuthenticationFilter.class)            
            // 10. 인증/권한 관련 예외 처리 설정
            .exceptionHandling(ex -> ex
              .authenticationEntryPoint((request, response, authException) -> {
                 log.warn("인증 엔트리포인트 호출됨: " + request.getRequestURI() + " - " + authException.getMessage());
                  
                 //  모든 API 요청에 대해 리다이렉트 대신 401 상태 코드만 반환
                   if (request.getRequestURI().startsWith("/api/")) {
                       response.setStatus(HttpServletResponse.SC_UNAUTHORIZED); // HTTP 401 설정
                       response.setContentType("application/json");
                       // 클라이언트에게 에러 메시지를 보냄 (필수)
                       response.getWriter().write("{\"status\": 401, \"error\": \"Unauthorized\", \"message\": \"JWT 인증은 성공했으나, Security Context에 문제가 있거나 접근 권한이 부족합니다.\"}");
                   } else {
                       // 웹 페이지 요청인 경우 로그인 페이지로 리다이렉트
                       response.sendRedirect(failUrl);
                   }
               })
                .accessDeniedHandler((request, response, accessDeniedException) -> {
                    //log.info("접근 권한 없음");
                    //response.sendRedirect("/login");  // 권한 없는 경우 로그인 페이지로 리다이렉트
                   if (request.getRequestURI().startsWith("/api/")) {
                        response.setStatus(HttpServletResponse.SC_FORBIDDEN); // HTTP 403
                        response.getWriter().write("{\"status\": 403, \"error\": \"Forbidden\", \"message\": \"접근 권한이 없습니다.\"}");
                        response.setContentType("application/json");
                    } else {
                        response.sendRedirect(failUrl);
                    }
                })
            )
            
            .build();
    }

    // [수정] CORS 설정 Bean 추가 - .cors(withDefaults())가 제대로 동작하도록
    @Bean
    public CorsConfigurationSource corsConfigurationSource() {
        CorsConfiguration configuration = new CorsConfiguration();
        // [수정] WebConfig.java와 origin 목록 통일 - HTTP/HTTPS 둘 다 허용
        configuration.setAllowedOrigins(Arrays.asList(
            "http://localhost:5500",
            "http://127.0.0.1:5500",
            // "http://dialogai.duckdns.org",
            // "https://dialogai.duckdns.org",
            // "http://dialogai.duckdns.org:5500"
            "http://dialogai.ddns.net",
            "https://dialogai.ddns.net"
        ));
        configuration.setAllowedMethods(Arrays.asList("GET", "POST", "PUT", "DELETE", "OPTIONS", "PATCH"));
        configuration.setAllowedHeaders(Arrays.asList("*"));
        configuration.setAllowCredentials(true);
        configuration.setMaxAge(3600L);
        
        UrlBasedCorsConfigurationSource source = new UrlBasedCorsConfigurationSource();
        source.registerCorsConfiguration("/**", configuration);
        return source;
    }
}