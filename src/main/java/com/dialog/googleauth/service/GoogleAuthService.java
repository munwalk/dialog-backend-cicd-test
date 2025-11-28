package com.dialog.googleauth.service;

import java.io.IOException;
import java.time.LocalDateTime;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.util.UriComponentsBuilder;

import com.dialog.exception.GoogleTokenExchangeException;
import com.dialog.exception.UserNotFoundException;
import com.dialog.googleauth.domain.GoogleAuthDTO;
import com.dialog.security.oauth2.CustomOAuth2User;
import com.dialog.token.domain.UserSocialToken;
import com.dialog.token.repository.UserSocialTokenRepository;
import com.dialog.user.domain.MeetUser;
import com.dialog.user.repository.MeetUserRepository;
import com.google.api.client.googleapis.auth.oauth2.GoogleAuthorizationCodeFlow;
import com.google.api.client.googleapis.auth.oauth2.GoogleTokenResponse;
import com.google.api.client.http.javanet.NetHttpTransport;
import com.google.api.client.json.jackson2.JacksonFactory;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

@Service
@Transactional(readOnly = true)
@RequiredArgsConstructor
@Slf4j
public class GoogleAuthService {

    private final MeetUserRepository meetUserRepository;
    private final UserSocialTokenRepository tokenRepository;

    @Value("${google.client.id}")
    private String clientId;

    @Value("${google.client.secret}")
    private String clientSecret;

    // [수정] 캘린더 연동용 별도 redirect URI 사용
    @Value("${google.calendar.link.redirect.uri}")
    private String redirectUri;

    private static final String SCOPE = "https://www.googleapis.com/auth/calendar.events";

public String generateAuthUrl(Long userId) {
        // userId를 Base64로 인코딩하여 state 값 생성 (보안 및 사용자 식별용)
        String state = Base64.getUrlEncoder().withoutPadding().encodeToString(userId.toString().getBytes());

        String authUrl = UriComponentsBuilder.fromUriString("https://accounts.google.com/o/oauth2/v2/auth")
            .queryParam("client_id", clientId)     // @Value로 주입받은 값 사용
            .queryParam("redirect_uri", redirectUri) // @Value로 주입받은 값 사용
            .queryParam("scope", SCOPE)
            .queryParam("response_type", "code")
            .queryParam("access_type", "offline")
            .queryParam("state", state)
            .queryParam("prompt", "consent") // 리프레시 토큰을 위해 필수
            .build().toUriString();
            
        log.info("생성된 구글 연동 URL: {}", authUrl); // 디버깅용 로그
        return authUrl;
    }

    public Long extractUserId(UserDetails userDetails) {
        if (userDetails == null) {
            throw new IllegalArgumentException("인증 정보가 null입니다.");
        }
        if (userDetails instanceof CustomOAuth2User customOAuth2User) {
            return customOAuth2User.getMeetuser().getId();
        }
        String email = userDetails.getUsername();
        MeetUser user = meetUserRepository.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("DB에서 사용자를 찾을 수 없습니다: " + email));
        return user.getId();
    }

    @Transactional
    public void exchangeCodeAndSaveToken(Long userId, String code) {
        try {
            // 구글 인증 흐름 생성
            GoogleAuthorizationCodeFlow flow = new GoogleAuthorizationCodeFlow.Builder(
                    new NetHttpTransport(), 
                    JacksonFactory.getDefaultInstance(),
                    clientId,      // @Value 값
                    clientSecret,  // @Value 값
                    Collections.singletonList(SCOPE))
                    .setAccessType("offline")
                    .build();

            // 인증 코드로 토큰 교환 요청
            GoogleTokenResponse response = flow.newTokenRequest(code)
                    .setRedirectUri(redirectUri) // @Value 값
                    .setGrantType("authorization_code")
                    .execute();

            String accessToken = response.getAccessToken();
            String refreshToken = response.getRefreshToken(); 
            Long expiresInSeconds = response.getExpiresInSeconds();
            LocalDateTime expiresAt = LocalDateTime.now().plusSeconds(expiresInSeconds);

            MeetUser user = meetUserRepository.findById(userId)
                    .orElseThrow(() -> new UserNotFoundException("사용자 없음 ID: " + userId));
            
            UserSocialToken token = tokenRepository.findByUser_IdAndProvider(userId, "google")
                    .orElseGet(() -> {
                        UserSocialToken newToken = new UserSocialToken();
                        newToken.setUser(user);
                        newToken.setProvider("google");
                        return newToken;
                    });

            if (refreshToken != null) {
                token.setRefreshToken(refreshToken);
            } else if (token.getRefreshToken() == null) {
                log.warn("Refresh Token이 발급되지 않았습니다. (이미 연동된 상태일 수 있음) userId={}", userId);
            }

            token.setAccessToken(accessToken);
            token.setExpiresAt(expiresAt);
            
            tokenRepository.save(token);
            log.info("구글 캘린더 연동 성공 (UserId: {})", userId);

        } catch (IOException e) {
            log.error("구글 토큰 교환 실패", e);
            throw new GoogleTokenExchangeException("Google 토큰 통신 오류: " + e.getMessage(), e);
        }
    }

    // [수정] JWT 인증 시 Principal이 String(email)인 경우를 위한 메서드 추가
    public Long extractUserIdByEmail(String email) {
        if (email == null || email.isBlank()) {
            throw new IllegalArgumentException("이메일이 비어있습니다.");
        }
        MeetUser user = meetUserRepository.findByEmail(email)
                .orElseThrow(() -> new UserNotFoundException("DB에서 사용자를 찾을 수 없습니다: " + email));
        return user.getId();
    }
}