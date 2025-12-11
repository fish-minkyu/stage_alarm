package com.example.stagealarm.config;


import com.example.stagealarm.jwt.JwtTokenFilter;
import com.example.stagealarm.jwt.JwtTokenUtils;
import com.example.stagealarm.oauth.OAuth2SuccessHandler;
import com.example.stagealarm.oauth.OAuth2UserServiceImpl;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;
import org.springframework.security.config.Customizer;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.annotation.web.configurers.ExceptionHandlingConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.security.web.access.intercept.AuthorizationFilter;

@Configuration
@RequiredArgsConstructor
public class WebSecurityConfig {
    private final JwtTokenUtils jwtTokenUtils;
    private final OAuth2SuccessHandler oAuth2SuccessHandler;
    private final OAuth2UserServiceImpl oAuth2UserService;
    @Bean
    public SecurityFilterChain securityFilterChain(
            HttpSecurity http
    ) throws Exception {
        Customizer<ExceptionHandlingConfigurer<HttpSecurity>> exceptionHandlingCustomizer = exceptionHandling -> {
            exceptionHandling
                    .accessDeniedHandler(new CustomAccessDeniedHandler())
                    .authenticationEntryPoint(new CustomAuthenticationEntryPoint());
        };
        http
                .exceptionHandling(exceptionHandlingCustomizer)
                // csrf 보안 헤제
                .csrf(AbstractHttpConfigurer::disable)
                .authorizeHttpRequests(auth -> auth

                        // 유저 권한
                        .requestMatchers(HttpMethod.GET, "/authenticated","/users", "/users/all",
                                "users/{id}", "/my-orders" ,"/orders/{id}/payment").authenticated()
                        .requestMatchers(HttpMethod.POST, "/shows/{id}/likes", "/shows/{id}", "/users/email/temp/send",
                                "/boards", "/board-comments/{boardId}", "/board-comments/{boardId}/reply/{commentId}",
                                "/toss/confirm-payment", "/orders/{id}/cancel",
                                "/artists/{id}/like", "/artists/{id}/subscribe", "/genres/{id}/subscribe").authenticated()
                        .requestMatchers(HttpMethod.DELETE, "/shows/{id}/likes", "/comments/{id}", "/users",
                                "/users/{id}", "/boards/{boardId}").authenticated()
                        .requestMatchers(HttpMethod.PATCH, "/comments/{id}", "/users", "/users/change-password").authenticated()
                        .requestMatchers(HttpMethod.PUT, "/boards/{boardId}", "/board-comments/{commentId}").authenticated()

                        // 어드민 권한
                        .requestMatchers(HttpMethod.GET, "/admin", "/orders", "/orders/{id}").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.PATCH, "/show/{id}/update", "/shows/{id}", "/items", "/artists/{id}").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.POST, "/shows", "/items", "/artists", "/artists/artist-check",
                                "/genres").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.DELETE, "/shows/{id}", "/items/{id}", "/artists/{id}", "/genres/{id}").hasRole("ADMIN")
                        .requestMatchers(HttpMethod.PUT, "/genres/{id}").hasRole("ADMIN")

                        .anyRequest()
                        .permitAll()
                )


                // OAuth 가 어떻게 실행하는지
                .oauth2Login(oauth2Login -> oauth2Login
                        .loginPage("/user/login")
                        .successHandler(oAuth2SuccessHandler)
                        .userInfoEndpoint(userInfo -> userInfo
                                .userService(oAuth2UserService))
                )

                // JWT 사용하기 때문에 보안 관련 세션 해제 (STATELESS: 상태를 저장하지 않음)
                .sessionManagement(session -> session
                        .sessionCreationPolicy(SessionCreationPolicy.STATELESS)
                )
                .addFilterBefore(
                        new JwtTokenFilter(jwtTokenUtils),
                        AuthorizationFilter.class
                );

        return http.build();
    }



}