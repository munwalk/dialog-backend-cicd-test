package com.dialog.config;

import org.springframework.context.annotation.Configuration;
import org.springframework.web.servlet.config.annotation.CorsRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration
public class WebConfig implements WebMvcConfigurer {
    @Override
    public void addCorsMappings(CorsRegistry registry) {
        registry.addMapping("/**") // /api/** 뿐만 아니라 전체 경로 허용 권장 (static 리소스 등 고려)
                .allowedOrigins(
                        "http://localhost:5500",      // 로컬 테스트용
                        "http://127.0.0.1:5500",      // 로컬 테스트용
                        // "http://dialogai.duckdns.org",      // 배포된 프론트엔드 도메인 (HTTP)
                        // "https://dialogai.duckdns.org",     // 혹시 HTTPS를 쓴다면 필수
                        // "http://dialogai.duckdns.org:5500"  // 만약 배포 후에도 5500 포트를 쓴다면
                        "http://dialogai.ddns.net",
                        "https://dialogai.ddns.net"
                )
                .allowedMethods("GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS") // "*" 대신 명시하는 것이 보안상 좋음
                .allowedHeaders("*")
                .allowCredentials(true) // 쿠키 인증 요청 허용 (중요)
                .maxAge(3600); // Preflight 요청 캐시 시간 (1시간)
    }
}